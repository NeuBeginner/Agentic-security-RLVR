"""The persistent monetary ledger of the R1 cycle.

The gate of ``benchmarks/r1_dispatch.py`` limits the **number** of dispatches per
container class in the memory of one process and prices a step statically. Both
controls are lost when the process ends, when a second stage runs in its own
process, or when a second process reserves the same money at the same time.

This module is the cross-process, cross-thread control of the cycle's money:

* one SQLite file holds the reservations of the cycle;
* every reservation is taken inside a ``BEGIN IMMEDIATE`` transaction, so the
  check and the write are **one** atomic step - two processes can therefore
  never both pass the same remaining budget; and
* the invariant

      spent_usd + reserved_usd + step_max_cost_usd <= cap_usd

  holds at every moment: across processes, across threads, across stages and
  across restarts. A reservation that would break it is refused immediately
  with the reason ``budget_cap_exceeded``.

The cap defaults to **20.00 USD**, the cycle cap of
``benchmarks/evidence/r1_cost_scenario.json``. The path and the cap are
overridable: ``AEGIS_R1_BUDGET_LEDGER_PATH`` names the ledger file and
``AEGIS_R1_BUDGET_CAP_USD`` overrides the cap. The default path lives outside
the repository (``~/.aegis/r1_budget_ledger.sqlite3``) so that it is persistent
and never part of a commit.

**The cap may be lowered, never raised.** The 20.00 USD of the cycle are a
**hard ceiling**: neither the constructor argument ``cap_usd`` nor the
environment variable ``AEGIS_R1_BUDGET_CAP_USD`` may push the cap above it. An
attempt to do so raises ``ValueError`` at the construction of the ledger, so the
cycle can never spend more than the approved 20.00 USD - not by an argument, not
by an environment variable and not by a second process that inherits either of
them.

**Nothing here approves anything.** The ledger only records and enforces the
money that the signed approval of the step already allowed: the reserved amount
is the signed ``estimate_usd`` of the step policy, and the ledger never widens
it. The ledger also holds no key: ``core/r1_approval.py`` remains the only
place where an approval is verified, and the rate card remains unapproved.

The money is kept in integer micro-USD (1e-6 USD) so that a sequence of
reservations and commits cannot drift through floating point.
"""

from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

#: The cycle cap in USD - the ``cycle_cap_usd`` of the cost scenario.
DEFAULT_CAP_USD = 20.0

#: The hard ceiling of the cap, in USD. The cap may be **lowered** below it -
#: never raised above it. The ceiling is a property of the approved cycle, not
#: a default: it is the same value as the default cap, and it is the value the
#: ledger refuses to exceed.
MAX_CAP_USD = DEFAULT_CAP_USD

#: The environment variable that names the ledger file.
LEDGER_PATH_ENV = "AEGIS_R1_BUDGET_LEDGER_PATH"

#: The environment variable that overrides the cap.
LEDGER_CAP_ENV = "AEGIS_R1_BUDGET_CAP_USD"

#: The default location of the ledger: persistent, per user, outside the repository.
DEFAULT_LEDGER_PATH = Path.home() / ".aegis" / "r1_budget_ledger.sqlite3"

#: One micro-USD. The ledger stores integers, never floats.
MICRO_USD = 1_000_000

#: The states of a reservation.
STATE_RESERVED = "reserved"
STATE_COMMITTED = "committed"
STATE_RELEASED = "released"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reservations (
    reservation_id TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL,
    step_id        TEXT NOT NULL,
    reserved_usd   INTEGER NOT NULL,
    charged_usd    INTEGER,
    state          TEXT NOT NULL,
    detail         TEXT NOT NULL DEFAULT '',
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS reservations_state ON reservations (state);
CREATE INDEX IF NOT EXISTS reservations_run ON reservations (run_id, step_id);
"""


class BudgetLedgerError(RuntimeError):
    """The base class of the ledger's failures."""


class BudgetCapExceeded(BudgetLedgerError):
    """The reservation would break the cap of the cycle.

    The refusal is immediate and complete: the money is not reserved, not
    spent and not released - it is never counted twice.
    """

    #: The machine-readable reason of the refusal. The gate maps it onto its
    #: own ``budget_cap_exceeded`` refusal.
    reason = "budget_cap_exceeded"

    def __init__(
        self,
        detail: str,
        *,
        spent_usd: float,
        reserved_usd: float,
        requested_usd: float,
        cap_usd: float,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.spent_usd = spent_usd
        self.reserved_usd = reserved_usd
        self.requested_usd = requested_usd
        self.cap_usd = cap_usd


class ReservationStateError(BudgetLedgerError):
    """The reservation does not exist or is not in the state the call needs."""


@dataclass(frozen=True)
class Reservation:
    """One reservation of the ledger."""

    reservation_id: str
    run_id: str
    step_id: str
    max_cost_usd: float
    state: str
    created_at: float

    def to_record(self) -> Dict[str, Any]:
        return {
            "reservation_id": self.reservation_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "max_cost_usd": self.max_cost_usd,
            "state": self.state,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class LedgerState:
    """The money of the cycle at one moment."""

    spent_usd: float
    reserved_usd: float
    cap_usd: float

    @property
    def available_usd(self) -> float:
        """The money that may still be reserved."""
        return self.cap_usd - self.spent_usd - self.reserved_usd

    def to_record(self) -> Dict[str, Any]:
        return {
            "spent_usd": self.spent_usd,
            "reserved_usd": self.reserved_usd,
            "cap_usd": self.cap_usd,
            "available_usd": self.available_usd,
        }


def _to_micro(value: float) -> int:
    """Convert USD into integer micro-USD. Refuses non-finite and negative values."""
    amount = float(value)
    if amount != amount or amount in (float("inf"), float("-inf")):
        raise ValueError(f"the cost {value!r} is not a finite amount")
    if amount < 0:
        raise ValueError(f"the cost {value!r} is negative")
    return int(round(amount * MICRO_USD))


def _to_usd(amount: int) -> float:
    return float(amount) / MICRO_USD


def is_billable_provider_object(obj: Any) -> bool:
    """True when the object is a real provider object - a Modal function or class.

    A **local double** costs nothing: it starts no container. The ledger is
    therefore charged for the objects that really start one - the objects of
    the provider SDK. The check looks at the module the object itself declares,
    so it survives the guard wrappers: the gate unwraps the guard before it
    asks, and the object behind the guard is the provider's own object.
    """
    module = (getattr(obj, "__module__", "") or "").split(".")[0]
    return module == "modal"


class BudgetLedger:
    """The persistent, atomic monetary ledger of the cycle.

    The ledger is opened lazily: constructing it touches no file. The first
    reservation creates the database and its schema.
    """

    def __init__(
        self,
        path: Optional[Any] = None,
        cap_usd: Optional[float] = None,
    ) -> None:
        raw_path = path if path is not None else os.environ.get(LEDGER_PATH_ENV)
        self.path = Path(raw_path or DEFAULT_LEDGER_PATH).expanduser()
        raw_cap = cap_usd if cap_usd is not None else os.environ.get(LEDGER_CAP_ENV)
        self.cap_usd = float(raw_cap) if raw_cap not in (None, "") else DEFAULT_CAP_USD
        if not self.cap_usd > 0:
            raise ValueError(f"the cap {self.cap_usd!r} is not a positive amount")
        if self.cap_usd > MAX_CAP_USD:
            raise ValueError(
                f"the cap {self.cap_usd!r} USD is above the hard ceiling of {MAX_CAP_USD} USD "
                "of the cycle - the cap may be lowered, never raised"
            )

    # -- the database ---------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            connection.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:  # pragma: no cover - a file system without WAL
            pass
        connection.executescript(_SCHEMA)
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """One write transaction. The write lock is taken before the check."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            connection.execute("COMMIT")
        finally:
            connection.close()

    @staticmethod
    def _totals(connection: sqlite3.Connection) -> Tuple[int, int]:
        """The spent and the reserved micro-USD of the whole ledger."""
        spent = connection.execute(
            "SELECT COALESCE(SUM(charged_usd), 0) FROM reservations WHERE state = ?",
            (STATE_COMMITTED,),
        ).fetchone()[0]
        reserved = connection.execute(
            "SELECT COALESCE(SUM(reserved_usd), 0) FROM reservations WHERE state = ?",
            (STATE_RESERVED,),
        ).fetchone()[0]
        return int(spent), int(reserved)

    # -- the operations -------------------------------------------------------------

    def reserve(self, run_id: str, step_id: str, max_cost_usd: float) -> Reservation:
        """Reserve ``max_cost_usd`` for one step of one run.

        The reservation is refused with :class:`BudgetCapExceeded` when the
        invariant ``spent + reserved + max_cost <= cap`` would be broken. The
        refusal happens **inside** the write transaction, so a concurrent
        reservation cannot slip between the check and the write.
        """
        amount = _to_micro(max_cost_usd)
        if amount > int(round(self.cap_usd * MICRO_USD)):
            raise BudgetCapExceeded(
                f"the step {step_id} of {run_id} would cost {max_cost_usd} USD, "
                f"which is more than the whole cap of {self.cap_usd} USD",
                spent_usd=0.0,
                reserved_usd=0.0,
                requested_usd=_to_usd(amount),
                cap_usd=self.cap_usd,
            )
        with self._transaction() as connection:
            spent, reserved = self._totals(connection)
            if spent + reserved + amount > int(round(self.cap_usd * MICRO_USD)):
                raise BudgetCapExceeded(
                    f"spent {spent} + reserved {reserved} + step {amount} exceeds the "
                    f"cap of {int(round(self.cap_usd * MICRO_USD))} micro-USD",
                    spent_usd=_to_usd(spent),
                    reserved_usd=_to_usd(reserved),
                    requested_usd=_to_usd(amount),
                    cap_usd=self.cap_usd,
                )
            reservation_id = uuid.uuid4().hex
            now = time.time()
            connection.execute(
                "INSERT INTO reservations (reservation_id, run_id, step_id, reserved_usd, "
                "charged_usd, state, detail, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, NULL, ?, '', ?, ?)",
                (reservation_id, str(run_id), str(step_id), amount, STATE_RESERVED, now, now),
            )
        return Reservation(
            reservation_id=reservation_id,
            run_id=str(run_id),
            step_id=str(step_id),
            max_cost_usd=_to_usd(amount),
            state=STATE_RESERVED,
            created_at=now,
        )

    def commit(self, reservation_id: str, actual_cost_usd: float) -> Reservation:
        """Charge the reservation with the cost of the step that ran.

        The amount is the **conservative** one: the reservation is charged even
        when the container failed or timed out, so a failed step never returns
        its money to the cycle. An amount above the reservation is charged as
        it is - the ledger then refuses the next reservation, and the
        overspend stays visible in the record.
        """
        amount = _to_micro(actual_cost_usd)
        with self._transaction() as connection:
            row = self._row(connection, reservation_id)
            if row is None:
                raise ReservationStateError(
                    f"the reservation {reservation_id!r} does not exist"
                )
            if row["state"] != STATE_RESERVED:
                raise ReservationStateError(
                    f"the reservation {reservation_id!r} is {row['state']!r}, not reserved"
                )
            now = time.time()
            connection.execute(
                "UPDATE reservations SET state = ?, charged_usd = ?, updated_at = ? "
                "WHERE reservation_id = ?",
                (STATE_COMMITTED, amount, now, reservation_id),
            )
            state = row["state"]
            run_id = row["run_id"]
            step_id = row["step_id"]
            created_at = row["created_at"]
        return Reservation(
            reservation_id=reservation_id,
            run_id=run_id,
            step_id=step_id,
            max_cost_usd=_to_usd(amount),
            state=state,
            created_at=created_at,
        )

    def release(self, reservation_id: str) -> Reservation:
        """Give the reserved money back - only for a step that never started.

        A release is refused for a reservation that was already committed: the
        money of a step that ran is never returned to the cycle.
        """
        with self._transaction() as connection:
            row = self._row(connection, reservation_id)
            if row is None:
                raise ReservationStateError(
                    f"the reservation {reservation_id!r} does not exist"
                )
            if row["state"] != STATE_RESERVED:
                raise ReservationStateError(
                    f"the reservation {reservation_id!r} is {row['state']!r}, not reserved"
                )
            now = time.time()
            connection.execute(
                "UPDATE reservations SET state = ?, updated_at = ? WHERE reservation_id = ?",
                (STATE_RELEASED, now, reservation_id),
            )
            run_id = row["run_id"]
            step_id = row["step_id"]
            created_at = row["created_at"]
        return Reservation(
            reservation_id=reservation_id,
            run_id=run_id,
            step_id=step_id,
            max_cost_usd=_to_usd(row["reserved_usd"]),
            state=STATE_RELEASED,
            created_at=created_at,
        )

    # -- the read-out ---------------------------------------------------------------

    def state(self) -> LedgerState:
        """The spent, the reserved and the available money of the cycle."""
        with self._transaction() as connection:
            spent, reserved = self._totals(connection)
        return LedgerState(
            spent_usd=_to_usd(spent),
            reserved_usd=_to_usd(reserved),
            cap_usd=self.cap_usd,
        )

    def reservations(self) -> List[Reservation]:
        """Every reservation of the ledger, newest first."""
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM reservations ORDER BY created_at DESC, reservation_id"
            ).fetchall()
        return [
            Reservation(
                reservation_id=row["reservation_id"],
                run_id=row["run_id"],
                step_id=row["step_id"],
                max_cost_usd=_to_usd(
                    row["charged_usd"] if row["charged_usd"] is not None else row["reserved_usd"]
                ),
                state=row["state"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def totals_by_run(self) -> Dict[str, Dict[str, float]]:
        """The spent and the reserved money per run - the stages share one cap."""
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT run_id, state, COALESCE(SUM(reserved_usd), 0) AS amount "
                "FROM reservations GROUP BY run_id, state"
            ).fetchall()
        totals: Dict[str, Dict[str, float]] = {}
        for row in rows:
            entry = totals.setdefault(row["run_id"], {"spent_usd": 0.0, "reserved_usd": 0.0})
            if row["state"] == STATE_COMMITTED:
                entry["spent_usd"] += _to_usd(int(row["amount"]))
            elif row["state"] == STATE_RESERVED:
                entry["reserved_usd"] += _to_usd(int(row["amount"]))
        return totals

    @staticmethod
    def _row(connection: sqlite3.Connection, reservation_id: str) -> Optional[sqlite3.Row]:
        return connection.execute(
            "SELECT * FROM reservations WHERE reservation_id = ?", (str(reservation_id),)
        ).fetchone()


__all__ = [
    "BudgetCapExceeded",
    "BudgetLedger",
    "BudgetLedgerError",
    "DEFAULT_CAP_USD",
    "DEFAULT_LEDGER_PATH",
    "LEDGER_CAP_ENV",
    "LEDGER_PATH_ENV",
    "LedgerState",
    "MAX_CAP_USD",
    "Reservation",
    "ReservationStateError",
    "is_billable_provider_object",
]
