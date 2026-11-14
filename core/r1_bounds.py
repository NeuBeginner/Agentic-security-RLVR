"""R1 declarations for the resource, lifecycle, autoscaler, egress and payload bounds
of the evidence-regeneration workflow (plan D26-D29).

The pre-dispatch estimate of the architecture plan multiplies five quantities: CPU
core-seconds, memory GiB-seconds, GPU seconds, stored GiB-months and egressed GiB.
Every one of them is a product of a **declared bound** and a **rate**. The rates are
approval inputs and deliberately live outside the repository; the bounds live here,
exactly once, each with the source that fixed it.

A bound is in one of two states:

* **declared** - a concrete value plus the provenance that fixed it (a plan section,
  an existing published configuration value, or a measured provider reading); or
* **REQUIRED-BUT-UNSET** - the value is not approved yet. Any path that would rely on
  it must refuse (fail closed) instead of falling back to a permissive provider
  default. A request is not a limit, and an unset limit is an unknown, not a small
  number (plan §5.6 g).

The module never invents a production value, never hardcodes a price, and never
performs a provider call.

**The guard.** The module also holds the guard of the deployment: the guard refuses a
provider dispatch while a required bound of the call site's container class is
required-but-unset, and it routes an authorised dispatch through the single gate of
``benchmarks/r1_dispatch.py``. The guard holds **no provider object**: the raw Modal
objects live in the module-private registry below, and the guard objects hold only an
opaque token and the call-site name - so no attribute of a guard yields a raw provider
callable. The guard is installed on the provider object's *own* ``remote``
(:func:`install_provider_guard`), so every reference to that object is gated too.

**No provider entry point is captured.** The installation replaces the object's own
``remote``, so the entry point the provider answers on is *not* kept: it is resolved
from the object's own class at the moment of the call, exactly the way the provider SDK
declares it. The repository therefore holds **no provider callable at all** - not in a
closure, not in a registry, not in an attribute of a guard. The resolver that performs
the call is private, it returns the *result* of the call and never the callable, and it
refuses to run outside the R1 dispatch gate - the check is against the **code object**
of the gate's dispatch method, and a code object cannot be forged, so the check is a
runtime fact and not a naming convention.

The same holds for the two other internals the gate needs: the unwrap helper (which
yields the provider object behind a guard) and the innermost provider call. Both are
private, and both refuse a call that does not come from the gate.

**The class-method boundary.** The provider SDK produces a **fresh** provider method on
every attribute access of a class instance (``modal/cls.py:442``), so a guard that
covers only the method it handed out leaves the next access unguarded. The guard is
therefore installed where the method is *produced*: the instance is moved to a subclass
that guards every provider method it resolves, so the method of the **raw** instance -
the one a caller reaches through the private registry - is guarded as well.

**The threat model.** The guard protects against a caller *inside this process* that
reaches the workflow through its own API, its registries, its guards and the provider
objects it holds. It is not a sandbox against arbitrary code in the same process: an
adversary who can execute code here can patch the guard, the registries or the gate
itself, and can reach the provider SDK through the SDK's own internals (the async
original of a function, the application's function registry, the class descriptor
protocol). That is a property of the language and of the process, not of this guard.
What the guard *does* guarantee - and what the evidence needs - is the auditable
property: **every provider entry point this repository hands out is gated, and no
provider callable is held anywhere in the repository.**
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from core.config import config

# --------------------------------------------------------------------------------------
# The two states of a bound
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Unset:
    """A required bound that is not approved yet.

    The instance is falsy on purpose: ``if not profile.memory_limit_mb`` reads as
    "there is no limit", which is exactly the fact the caller has to act on.
    """

    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return False

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"UNSET({self.reason})"


Bound = Union[int, float, str, Unset]


class BoundsNotApproved(RuntimeError):
    """Raised when a path would rely on a bound the maintainer has not approved."""

    def __init__(self, missing: Sequence[str], context: str = "") -> None:
        self.missing = list(missing)
        self.context = context
        where = f" for {context}" if context else ""
        detail = ", ".join(self.missing) if self.missing else "<none>"
        super().__init__(f"bounds not approved{where}: {detail}")


class UnauthorisedCallSite(BoundsNotApproved):
    """Raised when a provider call site is not part of the authorised trace.

    The repository contains provider callables that the evidence-regeneration
    workflow does **not** own: the T4 dev agent, the Slither worker, the fault
    injection worker, the diagnostics and the GRPO training path, the volume
    audit, and the audit-role method of the GPU class. They have no approved
    step, no declared bounds and no egress declaration, so dispatching them would
    start a billable container outside the approved budget. They are refused at
    the call boundary with the reason recorded here.
    """

    def __init__(self, function_name: str, reason: str) -> None:
        self.function_name = function_name
        self.reason = reason
        super().__init__([f"{function_name}: {reason}"], function_name)


def is_unset(value: Any) -> bool:
    """True when the value is a required-but-unset bound."""
    return isinstance(value, Unset)


def require(value: Bound, name: str, context: str = "") -> Any:
    """Return the value, or refuse when it is required-but-unset."""
    if is_unset(value):
        raise BoundsNotApproved([name], context)
    return value


# --------------------------------------------------------------------------------------
# Container classes (D26, D27)
# --------------------------------------------------------------------------------------

SANDBOX_CPU = "sandbox_cpu"
GPU_CLASS = "gpu"
PERSISTENCE = "persistence"

CONTAINER_CLASSES = (SANDBOX_CPU, GPU_CLASS, PERSISTENCE)


@dataclass(frozen=True)
class ResourceProfile:
    """The declared resource and lifecycle bounds of one container class.

    Every field is either a concrete value (with its provenance in ``provenance``) or
    an :class:`Unset`. ``missing_bounds()`` is the fail-closed gate: while it is not
    empty the class is not dispatchable and the estimate is unavailable.
    """

    container_class: str
    description: str

    # D26 - explicit request/limit pairs and an explicit lifecycle.
    cpu_request_cores: Bound
    cpu_limit_cores: Bound
    memory_request_mb: Bound
    memory_limit_mb: Bound
    timeout_sec: Bound
    startup_timeout_sec: Bound
    scaledown_window_sec: Bound

    # D27 - the autoscaler policy of the deployment.
    min_containers: int
    buffer_containers: int
    max_containers: int

    gpu_type: Optional[str]
    mounts_volume: bool

    provenance: Dict[str, str] = field(default_factory=dict)

    #: The bounds the estimate and the dispatch gate require.
    REQUIRED_BOUNDS: Tuple[str, ...] = (
        "cpu_request_cores",
        "cpu_limit_cores",
        "memory_request_mb",
        "memory_limit_mb",
        "timeout_sec",
        "startup_timeout_sec",
        "scaledown_window_sec",
    )

    def missing_bounds(self) -> List[str]:
        """The names of the required bounds that are not approved yet."""
        return [name for name in self.REQUIRED_BOUNDS if is_unset(getattr(self, name))]

    def billable_lifetime_sec(self) -> float:
        """``T_billable = startup_timeout + timeout + scaledown_window``.

        A request is not a limit, and an execution timeout is not the billable
        lifetime: the startup and the idle retention are billed too (plan §5.6 g).
        """
        missing = [
            name
            for name in ("startup_timeout_sec", "timeout_sec", "scaledown_window_sec")
            if is_unset(getattr(self, name))
        ]
        if missing:
            raise BoundsNotApproved(missing, self.container_class)
        return float(
            self.startup_timeout_sec + self.timeout_sec + self.scaledown_window_sec  # type: ignore[operator]
        )

    def cpu_limit(self) -> float:
        return float(require(self.cpu_limit_cores, "cpu_limit_cores", self.container_class))

    def memory_limit_gib(self) -> float:
        limit_mb = require(self.memory_limit_mb, "memory_limit_mb", self.container_class)
        return float(limit_mb) / 1024.0

    def modal_kwargs(self) -> Dict[str, Any]:
        """The decorator keyword arguments this class declares.

        A bound that is not approved is **not** replaced by a permissive default: the
        parameter is simply absent, and the absence is reported by
        :func:`missing_deployment_bounds`. The autoscaler policy is always declared -
        it is the part of the deployment that bounds the container count.
        """
        kwargs: Dict[str, Any] = {
            "min_containers": self.min_containers,
            "buffer_containers": self.buffer_containers,
            "max_containers": self.max_containers,
        }
        if not is_unset(self.cpu_limit_cores) and not is_unset(self.cpu_request_cores):
            kwargs["cpu"] = (float(self.cpu_request_cores), float(self.cpu_limit_cores))  # type: ignore[arg-type]
        elif not is_unset(self.cpu_request_cores):
            # The request is known, the limit is not approved: the request is kept
            # (it is the existing published configuration) and the missing limit is
            # reported as an unapproved bound.
            kwargs["cpu"] = float(self.cpu_request_cores)  # type: ignore[arg-type]
        if not is_unset(self.memory_limit_mb) and not is_unset(self.memory_request_mb):
            kwargs["memory"] = (int(self.memory_request_mb), int(self.memory_limit_mb))  # type: ignore[arg-type]
        elif not is_unset(self.memory_request_mb):
            kwargs["memory"] = int(self.memory_request_mb)  # type: ignore[arg-type]
        if not is_unset(self.startup_timeout_sec):
            kwargs["startup_timeout"] = int(self.startup_timeout_sec)  # type: ignore[arg-type]
        if not is_unset(self.scaledown_window_sec):
            kwargs["scaledown_window"] = int(self.scaledown_window_sec)  # type: ignore[arg-type]
        return kwargs

    def to_record(self) -> Dict[str, Any]:
        """A JSON-serialisable record of the declaration (approval record material)."""
        record: Dict[str, Any] = {"container_class": self.container_class, "description": self.description}
        for name in self.REQUIRED_BOUNDS:
            value = getattr(self, name)
            record[name] = None if is_unset(value) else value
            record[f"{name}.source"] = self.provenance.get(name)
        record["min_containers"] = self.min_containers
        record["buffer_containers"] = self.buffer_containers
        record["max_containers"] = self.max_containers
        record["gpu_type"] = self.gpu_type
        record["mounts_volume"] = self.mounts_volume
        record["missing_bounds"] = self.missing_bounds()
        return record


# The deployed union ceilings (D27). A ``max_containers`` is a property of the
# deployment, not of a step: the deployed value is the union of the caps of every
# authorised step and is never changed between the steps. The per-step cap is enforced
# client-side by the dispatch helper.
UNION_CEILING_SANDBOX_CPU = 48
UNION_CEILING_GPU = 32
UNION_CEILING_PERSISTENCE = 16

_PLAN = "plan §8.2.5 (D27)"

SANDBOX_CPU_PROFILE = ResourceProfile(
    container_class=SANDBOX_CPU,
    description="sandbox CPU - verify_exploit_remote / verify_replay_remote / model-cache prefetch",
    cpu_request_cores=config.SANDBOX_CPU_CORES,
    cpu_limit_cores=Unset(
        "the CPU limit is an approval input; without it the provider's default "
        "'request + 16' rule applies and the CPU term of the estimate is unbounded (D26)"
    ),
    memory_request_mb=config.SANDBOX_MEMORY_MB,
    memory_limit_mb=Unset(
        "the memory limit is an approval input; a forge compile of the published "
        "targets is not bounded by 2048 MiB, so the limit must be chosen explicitly "
        "and must not OOM-kill the run (D26)"
    ),
    timeout_sec=config.SANDBOX_TIMEOUT_SEC,
    startup_timeout_sec=Unset("the startup timeout is an approval input (D26)"),
    scaledown_window_sec=Unset(
        "the idle tail of the billable lifetime is an approval input (D26); the "
        "provider's published default is 60 s (modal.com/pricing, FAQ, read 2026-11-11)"
    ),
    min_containers=0,
    buffer_containers=0,
    max_containers=UNION_CEILING_SANDBOX_CPU,
    gpu_type=None,
    mounts_volume=False,
    provenance={
        "cpu_request_cores": "core/config.py:37 (published configuration)",
        "memory_request_mb": "core/config.py:38 (published configuration)",
        "timeout_sec": "core/config.py:36 (published configuration)",
        "min_containers": _PLAN,
        "buffer_containers": _PLAN,
        "max_containers": _PLAN,
    },
)

GPU_PROFILE = ResourceProfile(
    container_class=GPU_CLASS,
    description="GPU class - ProductionAuditAgent (H100)",
    cpu_request_cores=Unset(
        "the GPU class declares no cpu= today (modal_app.py), so it runs on the "
        "platform default request; the explicit request is an approval input (D26)"
    ),
    cpu_limit_cores=Unset("the CPU limit of the GPU container is an approval input (D26)"),
    memory_request_mb=Unset(
        "the GPU class declares no memory= today (modal_app.py); the explicit request "
        "is an approval input (D26)"
    ),
    memory_limit_mb=Unset(
        "the memory limit of the GPU container is an approval input (D26); the pinned "
        "model alone needs ~57 GiB in bf16, so the limit must not OOM-kill the load"
    ),
    timeout_sec=1200,
    startup_timeout_sec=Unset(
        "the startup timeout of the GPU container is an approval input (D26); the "
        "model load happens inside the container startup"
    ),
    scaledown_window_sec=Unset("the idle tail of the billable lifetime is an approval input (D26)"),
    min_containers=0,
    buffer_containers=0,
    max_containers=UNION_CEILING_GPU,
    gpu_type=config.AUDIT_GPU_TYPE,
    mounts_volume=True,
    provenance={
        "timeout_sec": "modal_app.py:78 (the deployed value of the GPU class)",
        "gpu_type": "core/config.py:19 (published configuration)",
        "min_containers": _PLAN,
        "buffer_containers": _PLAN,
        "max_containers": _PLAN,
    },
)

PERSISTENCE_PROFILE = ResourceProfile(
    container_class=PERSISTENCE,
    description="persistence function - record_trajectory_remote",
    cpu_request_cores=Unset(
        "the persistence function declares no cpu= today (modal_app.py), so it runs on "
        "the 0.125-core default request; the explicit request is an approval input (D26)"
    ),
    cpu_limit_cores=Unset("the CPU limit of the persistence container is an approval input (D26)"),
    memory_request_mb=Unset(
        "the persistence function declares no memory= today (modal_app.py), so it runs "
        "on the 128 MiB default request; the explicit request is an approval input (D26)"
    ),
    memory_limit_mb=Unset("the memory limit of the persistence container is an approval input (D26)"),
    timeout_sec=60,
    startup_timeout_sec=Unset("the startup timeout of the persistence container is an approval input (D26)"),
    scaledown_window_sec=Unset("the idle tail of the billable lifetime is an approval input (D26)"),
    min_containers=0,
    buffer_containers=0,
    max_containers=UNION_CEILING_PERSISTENCE,
    gpu_type=None,
    mounts_volume=True,
    provenance={
        "timeout_sec": "modal_app.py:698 (the deployed value of the persistence function)",
        "min_containers": _PLAN,
        "buffer_containers": _PLAN,
        "max_containers": _PLAN,
    },
)

PROFILES: Dict[str, ResourceProfile] = {
    SANDBOX_CPU: SANDBOX_CPU_PROFILE,
    GPU_CLASS: GPU_PROFILE,
    PERSISTENCE: PERSISTENCE_PROFILE,
}


def profile_for(container_class: str) -> ResourceProfile:
    return PROFILES[container_class]


def deployed_max_containers(container_class: str) -> int:
    """The provider-enforced concurrency ceiling of the deployment (D27)."""
    return PROFILES[container_class].max_containers


# --------------------------------------------------------------------------------------
# Egress (D29)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class EgressPolicy:
    """The per-container egress declaration of one dispatched function.

    ``payload_cap_bytes`` bounds the bytes the workload itself sends out;
    ``protocol_allowance_bytes`` is the provider's control-plane and volume
    data-path overhead, which is **added on top** of the payload cap for every
    container of every class - a payload zero is not a total zero by implication.
    """

    function_name: str
    container_class: str
    payload_cap_bytes: Bound
    protocol_allowance_bytes: Bound
    block_network: bool
    offline: bool
    basis: str


_PROTOCOL_UNSET = Unset(
    "the protocol allowance is an approval input with its source and date; if it "
    "cannot be bounded the affected step is not dispatchable (D29)"
)

#: The provider's own definition of egress, with its source and reading date.
_PROVIDER_INGRESS_NOTE = (
    "the provider bills outbound traffic as egress; a download into the container "
    "is ingress and is not billed at the egress rate, and a read or a write of a "
    "Modal Volume is not egress either "
    "(https://modal.com/docs/guide/network-egress-billing, read 2026-11-12)"
)

EGRESS_POLICIES: Dict[str, EgressPolicy] = {
    "verify_exploit_remote": EgressPolicy(
        function_name="verify_exploit_remote",
        container_class=SANDBOX_CPU,
        payload_cap_bytes=0,
        protocol_allowance_bytes=_PROTOCOL_UNSET,
        block_network=True,
        offline=True,
        basis="provider-enforced block_network declaration on the exact function; "
        "the sandbox functions mount no volume and the toolchain is installed at "
        "build time (plan §8.2.5, D29)",
    ),
    "verify_replay_remote": EgressPolicy(
        function_name="verify_replay_remote",
        container_class=SANDBOX_CPU,
        payload_cap_bytes=0,
        protocol_allowance_bytes=_PROTOCOL_UNSET,
        block_network=True,
        offline=True,
        basis="provider-enforced block_network declaration on the exact function (D29)",
    ),
    "record_trajectory_remote": EgressPolicy(
        function_name="record_trajectory_remote",
        container_class=PERSISTENCE,
        payload_cap_bytes=0,
        protocol_allowance_bytes=_PROTOCOL_UNSET,
        block_network=False,
        offline=True,
        basis="0 external by construction: the function opens a file and commits the "
        "volume and makes no outbound request (modal_app.py:700-712; D29)",
    ),
    "ProductionAuditAgent.generate_solidity_exploit": EgressPolicy(
        function_name="ProductionAuditAgent.generate_solidity_exploit",
        container_class=GPU_CLASS,
        payload_cap_bytes=0,
        protocol_allowance_bytes=_PROTOCOL_UNSET,
        block_network=True,
        offline=True,
        basis="provider-enforced block_network on the whole GPU class (the parameter "
        "exists for app.cls in modal/app.py:1102 and reaches the provider as "
        "api_pb2.Function.block_network, modal/_functions.py:1044); the offline "
        "environment and the verified cache manifest are the second, independent "
        "layer (D29)",
    ),
    "ProductionAuditAgent.refine_solidity_exploit": EgressPolicy(
        function_name="ProductionAuditAgent.refine_solidity_exploit",
        container_class=GPU_CLASS,
        payload_cap_bytes=0,
        protocol_allowance_bytes=_PROTOCOL_UNSET,
        block_network=True,
        offline=True,
        basis="the same provider-enforced block_network declaration of the GPU class "
        "(D29)",
    ),
    "ProductionAuditAgent.audit_target_contract": EgressPolicy(
        function_name="ProductionAuditAgent.audit_target_contract",
        container_class=GPU_CLASS,
        payload_cap_bytes=0,
        protocol_allowance_bytes=_PROTOCOL_UNSET,
        block_network=True,
        offline=True,
        basis="the method shares the GPU class, whose block_network declaration "
        "covers every method of it; the call site itself is not part of the "
        "authorised trace and is refused (D29)",
    ),
    "prefetch_model_cache_remote": EgressPolicy(
        function_name="prefetch_model_cache_remote",
        container_class=SANDBOX_CPU,
        payload_cap_bytes=0,
        protocol_allowance_bytes=_PROTOCOL_UNSET,
        block_network=False,
        offline=False,
        basis="the outbound payload of the prefetch is zero by construction: the "
        "model is downloaded (that is ingress - see INGRESS_POLICIES) and written to "
        "the volume (a volume write is not egress). Only the provider's "
        "control-plane overhead is outbound, and it is declared separately (D29; "
        + _PROVIDER_INGRESS_NOTE
        + ")",
    ),
}


@dataclass(frozen=True)
class IngressPolicy:
    """The **inbound** byte cap of one dispatched function.

    The provider bills **outbound** traffic as egress. A download *into* the
    container is ingress and is not billed at the egress rate, and a read or a
    write of a Modal Volume is not egress either
    (https://modal.com/docs/guide/network-egress-billing, read 2026-11-12).

    The inbound cap is therefore declared **separately** from the outbound one:
    it is a bound like any other, and it is never charged at the egress rate.
    """

    function_name: str
    container_class: str
    ingress_cap_bytes: Bound
    basis: str


#: The inbound byte caps of the dispatched functions. Only the prefetch has one:
#: it is the only container of the cycle that downloads anything.
INGRESS_POLICIES: Dict[str, IngressPolicy] = {
    "prefetch_model_cache_remote": IngressPolicy(
        function_name="prefetch_model_cache_remote",
        container_class=SANDBOX_CPU,
        ingress_cap_bytes=Unset(
            "the inbound cap is pinned_bytes x (1 + R_download); neither the retry "
            "count nor the pinned revision's byte size is approved yet (D29)"
        ),
        basis="the only inbound traffic of the cycle is the model download of the "
        "prefetch: it is ingress, not egress, so it is declared and bounded "
        "separately from the outbound traffic (D29)",
    ),
}


def ingress_policy(function_name: str) -> Optional[IngressPolicy]:
    return INGRESS_POLICIES.get(function_name)


def egress_policy(function_name: str) -> Optional[EgressPolicy]:
    return EGRESS_POLICIES.get(function_name)


#: The container classes that are deployed as a Modal **class**. A class declares
#: one network policy for all of its methods; the classes that are deployed as a
#: set of separate functions declare their policy per function.
CLASS_CONTAINER_CLASSES: Tuple[str, ...] = (GPU_CLASS,)


def class_network_policy(container_class: str) -> Optional[bool]:
    """The provider-level network blocking declared for a container class.

    A Modal **class** declares one network policy for all of its methods, so the
    declaration of the class is the common policy of its methods. A disagreement
    between two methods of the same class is a declaration error and is refused.

    A container class that is deployed as a set of separate functions has no class
    policy: every one of its functions declares its own. ``None`` means "not a
    class deployment".
    """
    if container_class not in CLASS_CONTAINER_CLASSES:
        return None
    policies = [
        policy.block_network
        for policy in EGRESS_POLICIES.values()
        if policy.container_class == container_class
    ]
    if not policies:
        raise BoundsNotApproved(
            [f"the {container_class} class declares no egress policy"], container_class
        )
    if len(set(policies)) != 1:
        raise BoundsNotApproved(
            [f"the {container_class} methods declare conflicting network policies"],
            container_class,
        )
    return bool(policies[0])


# --------------------------------------------------------------------------------------
# The storage allowance (D28) - the maintainer's rule of the free tier
# --------------------------------------------------------------------------------------

#: The provider's published free allowance of volume storage, in GiB **per month**
#: (1 TiB). Inside the allowance the storage of a run costs USD 0; above it the
#: published list price applies. The allowance is an **account-level** monthly
#: allowance: it is applied **once** to the cycle's footprint, never per stage.
STORAGE_FREE_ALLOWANCE_GIB_PER_MONTH = 1024.0

STORAGE_FREE_ALLOWANCE_SOURCE = (
    "modal.com/pricing: 'Volumes $0.09 / GiB / mo *includes 1 TiB / mo free' "
    "(read 2026-11-11)"
)


# --------------------------------------------------------------------------------------
# The autoscaler declaration (D27) - the four fields the read-back must cover
# --------------------------------------------------------------------------------------

#: The four autoscaler fields the read-back has to cover. All four are mandatory:
#: a missing, None or malformed field is a refusal, never a partial read.
AUTOSCALER_FIELDS: Tuple[str, ...] = (
    "min_containers",
    "max_containers",
    "buffer_containers",
    "scaledown_window",
)


def declared_autoscaler_settings(profile: ResourceProfile) -> Dict[str, Optional[int]]:
    """The autoscaler settings a class declares, field by field.

    A field that is not approved is ``None``: the read-back cannot compare what is
    not declared, and a partial comparison would let an unapproved field pass.
    """
    scaledown = profile.scaledown_window_sec
    return {
        "min_containers": int(profile.min_containers),
        "max_containers": int(profile.max_containers),
        "buffer_containers": int(profile.buffer_containers),
        "scaledown_window": None if is_unset(scaledown) else int(scaledown),  # type: ignore[arg-type]
    }


# --------------------------------------------------------------------------------------
# Producer-enforced payload cap (D28)
# --------------------------------------------------------------------------------------

MAX_TRAJECTORY_PAYLOAD_BYTES: Bound = Unset(
    "the hard byte cap of one trajectory payload is an approval input; the "
    "persistence function refuses a larger payload instead of writing it (D28)"
)


def assert_payload_within_cap(payload_bytes: int, context: str = "trajectory payload") -> None:
    """Refuse a payload that exceeds the declared cap (fail closed)."""
    cap = require(MAX_TRAJECTORY_PAYLOAD_BYTES, "MAX_TRAJECTORY_PAYLOAD_BYTES", context)
    if payload_bytes > int(cap):
        raise BoundsNotApproved([f"payload of {payload_bytes} bytes exceeds the declared cap"], context)


# --------------------------------------------------------------------------------------
# The pinned model (D29, R2p)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PinnedModel:
    repo_id: str
    revision: str
    bytes_total: int
    measured_at: str
    source: str


PINNED_MODEL = PinnedModel(
    repo_id=config.AUDIT_GPU_MODEL,
    revision="655425b794ae4a19f2ea16fa480c6b39102721ee",
    bytes_total=61_077_997_602,
    measured_at="2026-11-11",
    source="https://huggingface.co/api/models/qtum/Qwen3-Coder-30B-A3B-Audit?blobs=true",
)

#: The retry allowance of the prefetch step - an approval input (D29).
DOWNLOAD_RETRY_ALLOWANCE: Bound = Unset(
    "R_download is an approval input: the declared maximum number of download "
    "attempts of the prefetch step (D29)"
)


def prefetch_ingress_cap_bytes() -> int:
    """``pinned_bytes x (1 + R_download)`` - the prefetch's per-container **ingress** cap.

    These are the bytes the container *downloads*: the model download is
    ingress and is not billed at the egress rate, so the cap is an ingress cap
    and not a payload cap (D29).
    """
    retry = require(DOWNLOAD_RETRY_ALLOWANCE, "DOWNLOAD_RETRY_ALLOWANCE", "prefetch")
    return int(PINNED_MODEL.bytes_total * (1 + float(retry)))


# --------------------------------------------------------------------------------------
# The offline GPU cache (D29)
# --------------------------------------------------------------------------------------

#: The environment that forces the transformers stack to read the cache only.
OFFLINE_ENV: Dict[str, str] = {
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
}

#: The manifest of the pinned revision, written by R2p on the volume.
MODEL_CACHE_MANIFEST_PATH = "/vol/models/model_cache_manifest.json"


def verify_model_cache_manifest(
    cache_dir: str,
    manifest: Dict[str, Any],
    listdir=os.listdir,
    getsize=os.path.getsize,
) -> Dict[str, Any]:
    """Check the volume's model cache against the recorded manifest.

    With ``local_files_only=True`` the hub client raises instead of downloading, so
    an incomplete cache has to fail the container **closed** rather than quietly
    download the model again (D29).

    ``listdir``/``getsize`` are injectable so the check is testable without a volume.
    """
    if "repo_id" in manifest and manifest.get("repo_id") != PINNED_MODEL.repo_id:
        return {
            "status": "FAILED",
            "reason": "the manifest repo_id does not match PINNED_MODEL.repo_id",
            "missing": [],
            "mismatched": ["repo_id"],
            "checked": 0,
        }
    if "revision" in manifest and manifest.get("revision") != PINNED_MODEL.revision:
        return {
            "status": "FAILED",
            "reason": "the manifest revision does not match PINNED_MODEL.revision",
            "missing": [],
            "mismatched": ["revision"],
            "checked": 0,
        }
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return {
            "status": "FAILED",
            "reason": "the manifest carries no file list",
            "missing": [],
            "checked": 0,
        }
    missing: List[str] = []
    mismatched: List[str] = []
    try:
        present = set(listdir(cache_dir))
    except OSError:
        present = set()
    for entry in files:
        name = entry.get("path")
        size = entry.get("size")
        if not name or size is None:
            mismatched.append(str(name))
            continue
        full_path = os.path.join(cache_dir, name)
        if name not in present and not os.path.exists(full_path):
            missing.append(name)
            continue
        try:
            actual = getsize(full_path)
        except OSError:
            missing.append(name)
            continue
        if int(actual) != int(size):
            mismatched.append(name)
            continue
        expected_sha = entry.get("sha256")
        if expected_sha is not None and os.path.isfile(full_path):
            hasher = hashlib.sha256()
            try:
                with open(full_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        hasher.update(chunk)
                if hasher.hexdigest().lower() != str(expected_sha).lower():
                    mismatched.append(name)
            except OSError:
                missing.append(name)
    status = "PASSED" if not missing and not mismatched else "FAILED"
    return {
        "status": status,
        "reason": None if status == "PASSED" else "the model cache does not match the recorded manifest",
        "missing": missing,
        "mismatched": mismatched,
        "checked": len(files),
    }


# --------------------------------------------------------------------------------------
# The deployed functions and the dispatch guard
# --------------------------------------------------------------------------------------

#: The functions this workflow is allowed to dispatch, and their container class.
FUNCTION_CLASS: Dict[str, str] = {
    "verify_exploit_remote": SANDBOX_CPU,
    "verify_replay_remote": SANDBOX_CPU,
    "record_trajectory_remote": PERSISTENCE,
    "prefetch_model_cache_remote": SANDBOX_CPU,
    "ProductionAuditAgent.generate_solidity_exploit": GPU_CLASS,
    "ProductionAuditAgent.refine_solidity_exploit": GPU_CLASS,
}

#: The provider call sites of this repository that are **not** part of the
#: authorised evidence-regeneration trace. Every one of them is refused at the call
#: boundary: none of them has an approved step, a declared bound set or an egress
#: declaration, and dispatching one would start a billable container outside the
#: approved budget. The registry is the inventory of the refused surface - it is
#: the reason a refusal can name what it refuses.
UNAUTHORISED_CALL_SITES: Dict[str, str] = {
    "run_slither_remote": (
        "the Slither worker is not one of the plan's stages; it has no declared "
        "bounds and no egress declaration"
    ),
    "verify_replay_fault_injection_remote": (
        "the fault-injection worker is a test fixture of the replay path, not an "
        "authorised step; it may not start a billable container"
    ),
    "audit_volume_trajectories_remote": (
        "the read-only volume audit is a diagnostic of the stored trajectories, not "
        "an authorised step"
    ),
    "diagnostic_grpo_forward_remote": (
        "the GRPO diagnostic forward pass is a diagnostic, not an authorised step; "
        "it runs the dev model on the GPU"
    ),
    "train_grpo_remote": (
        "the GRPO training path is blocked by the supervisor and is not an "
        "authorised step"
    ),
    "DevReasoningAgent.generate_solidity_exploit": (
        "the T4 dev agent is not part of the authorised trace: it has no declared "
        "bounds, and it downloads its model from the hub"
    ),
    "DevReasoningAgent.refine_solidity_exploit": (
        "the T4 dev agent is not part of the authorised trace: it has no declared "
        "bounds, and it downloads its model from the hub"
    ),
    "ProductionAuditAgent.audit_target_contract": (
        "the audit-role method of the GPU class is not one of the authorised stages; "
        "only the exploit generation and the refinement are"
    ),
    "cpu_smoke": (
        "the Iteration 19 runtime smoke app is a separate deployment that is not "
        "part of the authorised trace: it has no approved step policy, no declared "
        "bounds and no egress declaration, so its live invocation is refused until "
        "a separate maintainer approval exists"
    ),
    "audit_contract": (
        "the audit entry point of the CPU-only audit service (modal_cpu_audit_app.py) "
        "is a separate deployment that is not part of the authorised trace: it has no "
        "approved step policy and no declared bounds of the R1 plan, so the R1 gate "
        "refuses it at the call boundary and the service is only reachable through "
        "its own driver, which refuses the live invocation without a separate "
        "maintainer approval"
    ),
    "probe_environment": (
        "the environment probe of the CPU-only audit service (modal_cpu_audit_app.py) "
        "is a diagnostic of that separate deployment, not an authorised step of the "
        "R1 trace, so it is refused at the call boundary"
    ),
    "read_saved_result": (
        "the read-back of the CPU-only audit service (modal_cpu_audit_app.py) belongs "
        "to that separate deployment and is not an authorised step of the R1 trace, "
        "so it is refused at the call boundary"
    ),
}


def assert_authorised_call_site(function_name: str) -> str:
    """Return the container class of an authorised call site, or refuse.

    This is the first gate of every provider call: a call site that is not part of
    the authorised trace is refused with the reason of the registry, before any
    budget, bound or egress question is asked.
    """
    container_class = FUNCTION_CLASS.get(function_name)
    if container_class is not None:
        return container_class
    reason = UNAUTHORISED_CALL_SITES.get(function_name)
    if reason is None:
        reason = (
            "it is not a declared dispatchable function of the evidence-regeneration "
            "workflow"
        )
    raise UnauthorisedCallSite(function_name, reason)

#: The objects the deployment actually exposes, registered at import time.
DEPLOYED_FUNCTIONS: Dict[str, Any] = {}


def register_deployed_function(name: str, obj: Any) -> None:
    """Register the deployed object of a dispatchable function."""
    DEPLOYED_FUNCTIONS[name] = obj


#: Marker used to recognise a provider callable through a guard wrapper.
PROVIDER_CALLABLE_MARKER = "_r1_provider_callable"


def is_provider_callable(obj: Any) -> bool:
    """True when the object is a real provider callable (and not a local double).

    The distinction matters: a local double costs nothing, a provider callable
    starts a billable container. A guard wrapper keeps the marker of the object it
    wraps and answers for itself, so the check survives the wrapper.
    """
    reacher = getattr(obj, "r1_reaches_provider", None)
    if callable(reacher):
        return bool(reacher())
    if getattr(obj, PROVIDER_CALLABLE_MARKER, False):
        return True
    module = (type(obj).__module__ or "").split(".")[0]
    return module == "modal"


# --------------------------------------------------------------------------------------
# The provider registry - the one place that holds a raw provider object
# --------------------------------------------------------------------------------------
#
# **Why a registry and not an attribute.** The R1 review named four bypasses: the
# guard wrappers kept the raw Modal objects in their own instance dictionaries
# (``_fn``, ``_obj``, ``_cls``), so a caller could reach the raw provider callable
# and call it without the gate. A renamed attribute, a name-mangled attribute or an
# attribute that "callers are not supposed to inspect" would not close that hole.
#
# The guard therefore keeps **no reference to a provider object at all**: the raw
# objects live in the module-private registries below, and the guard objects hold
# only an opaque token and the call-site name. There is no attribute of a guard
# object, of a guarded class or of a guarded class instance that yields a raw
# provider object - and an attribute that starts with an underscore is refused
# outright instead of being delegated to the raw object.
#
# The registries hold **objects**, never callables. A callable in a registry would
# be an invocable provider entry point for whoever reads it, so the entry point is
# never stored: it is resolved from the provider object's own class at the moment
# of the call (see :func:`_call_provider_entry_point`).
#
# The registries are the trust boundary of the guard. Python has no private
# memory, so a caller that deliberately imports this module and reads its
# underscore-prefixed registries can still reach a provider object; that is a
# property of the language, not of this guard. What the guard *does* guarantee is
# the property the evidence needs: **every provider entry point the repository
# hands out is gated**. The guard is installed on the provider object's *own*
# ``remote`` (see :func:`install_provider_guard`), so even the raw object - from
# wherever it is reached - refuses a call while the bounds are unapproved and
# routes an approved call through the single gate.

#: The provider objects the guard wraps, by an opaque token.
_GUARDED_OBJECTS: Dict[str, Any] = {}

#: The provider objects that are installed under their call-site name.
_INSTALLED_OBJECTS: Dict[str, Any] = {}

#: The guarded class instances, by identity: the token of the raw instance and
#: the name of its class. The raw instance itself stays in ``_GUARDED_OBJECTS``.
_GUARDED_CLASS_INSTANCES: Dict[int, Dict[str, Any]] = {}

#: The subclasses that carry the guard of a provider class, by their class.
_GUARDED_SUBCLASSES: Dict[type, type] = {}


def _gate_dispatch_code() -> Optional[Any]:
    """The code object of the R1 gate's dispatch method.

    The internals of this module are callable from that code object and from
    nowhere else. A code object cannot be forged, so the check that uses it is
    a runtime fact and not a naming convention.
    """
    try:
        from benchmarks.r1_dispatch import DispatchGate
    except Exception:
        # The gate lives in the producer's package: the container image of the
        # deployment carries only ``core`` and ``sandbox``. There the gate is
        # not importable, and every internal call is refused (fail closed).
        return None
    return DispatchGate.dispatch.__code__


def _assert_called_by_the_gate(function_name: str, what: str, depth: int = 2) -> None:
    """Refuse an internal call that does not come from the R1 dispatch gate.

    The caller is checked against the **code object** of the gate's dispatch
    method. The provider entry point, the provider object behind a guard and
    the innermost provider call are reachable from the gate only - not through
    the public API of this module, not through a guard and not through a
    registry.

    ``depth`` is the number of frames between this check and the dispatch
    method: 2 for a helper the gate calls directly, 3 for a helper the gate
    calls through another helper of this module.
    """
    reason = f"{what} may only be called from the R1 dispatch gate"
    try:
        caller = sys._getframe(depth)
    except Exception:  # pragma: no cover - CPython always has _getframe
        raise UnauthorisedCallSite(function_name, reason)
    expected = _gate_dispatch_code()
    if expected is None or caller.f_code is not expected:
        raise UnauthorisedCallSite(function_name, reason)


def _declares_entry_point(obj: Any) -> bool:
    """True when the object's own class declares a ``remote`` entry point.

    The check is the installation's fail-closed condition: an object without
    an entry point cannot be guarded, and the deployment must not start with an
    unguarded provider object.
    """
    return any("remote" in klass.__dict__ for klass in type(obj).__mro__)


def _call_provider_entry_point(obj: Any, *args: Any, **kwargs: Any) -> Any:
    """Call the provider's own entry point of ``obj``.

    The entry point is **resolved at the moment of the call** from the object's
    own class - the way the provider SDK declares it - and it is never
    captured: it is in no closure, in no registry and in no attribute of this
    module. The function returns the **result** of the call and never the
    callable, and only the R1 gate may call it: the caller is checked against
    the code object of the gate's dispatch method.

    A **substituted double** is the one exception: it is a local function that
    was put on a guard instead of the provider entry point. It starts no
    container and costs nothing, so it is called directly.
    """
    _assert_called_by_the_gate("<unknown>", "the provider entry point", depth=3)
    if isinstance(obj, _SubstitutedRemote):
        return obj.__dict__["remote"](*args, **kwargs)
    for klass in type(obj).__mro__:
        descriptor = klass.__dict__.get("remote")
        if descriptor is None:
            continue
        getter = getattr(descriptor, "__get__", None)
        if getter is None:
            continue
        return getter(obj, type(obj))(*args, **kwargs)
    raise UnauthorisedCallSite(
        "<unknown>",
        "the provider object declares no 'remote' entry point",
    )


def _register_guarded_object(obj: Any) -> str:
    """Register a provider object and return the opaque token that names it."""
    token = uuid.uuid4().hex
    _GUARDED_OBJECTS[token] = obj
    return token


def _guarded_object(token: str) -> Any:
    """The provider object of a token - or a refusal."""
    try:
        return _GUARDED_OBJECTS[token]
    except KeyError as exc:  # pragma: no cover - the registry holds every token
        raise UnauthorisedCallSite(
            "<unknown>",
            "the guarded provider object is not registered any more",
        ) from exc


def is_installed_call_site(function_name: str, fn: Any) -> bool:
    """True when the object is the provider object installed under this name.

    An installed call site is dispatched through the entry point that was
    captured before the guard was installed on the object's own ``remote``.
    """
    return (
        function_name in _INSTALLED_OBJECTS
        and fn is _INSTALLED_OBJECTS.get(function_name)
    )


def _perform_provider_call(function_name: str, fn: Any, *args: Any, **kwargs: Any) -> Any:
    """The provider call itself - the innermost step of an authorised dispatch.

    The R1 gate calls this, and nothing else may: the call is checked against
    the **code object** of the gate's dispatch method, so the provider entry
    point, the provider object behind a guard and the raw provider method of a
    class stay unreachable from the rest of the repository.

    The entry point of the provider is resolved here, at the moment of the
    call, from the provider object's own class. It is never captured: the
    repository holds no provider callable at all.
    """
    _assert_called_by_the_gate(function_name, "the provider call")
    return _call_provider_entry_point(fn, *args, **kwargs)


class _SubstitutedRemote:
    """A local double that was substituted on a guard.

    A substituted ``remote`` starts no container and costs nothing, so the
    dispatch contract of a provider call does not apply to it: it is passed
    through and counted, exactly as it was before the guard was reworked. The
    double itself is the guard's instance attribute - it is not a provider
    object and the wrapper hands out no reference to it.
    """

    def __init__(self, double: Any) -> None:
        self.__dict__["remote"] = double


def _unwrap_guard(fn: Any) -> Any:
    """The provider object behind a guard - or the object itself.

    The gate calls this before it dispatches, so that a guarded call is
    dispatched **once**: the gate holds the provider object, not the guard that
    would route the call back into the gate. A second pass through the gate
    would take the concurrency semaphore twice and stall the dispatch.

    A guard whose ``remote`` was substituted by a local double yields that
    double: it is not a provider call and must not be treated as one.

    The helper is private and the gate is its only caller: for a class method
    it yields the **raw** provider method, whose own ``remote`` is not
    guarded, so it may not be a public accessor of this module.
    """
    _assert_called_by_the_gate("<unknown>", "the unwrap helper")
    if isinstance(fn, GuardedRemote):
        substituted = fn.substituted_remote()
        if substituted is not None:
            return _SubstitutedRemote(substituted)
        return _guarded_object(fn.__dict__["_object_token"])
    if isinstance(fn, GuardedClassMethod):
        substituted = fn.substituted_remote()
        if substituted is not None:
            return _SubstitutedRemote(substituted)
        instance = _guarded_object(fn.__dict__["_instance_token"])
        return _raw_class_method(instance, fn.__dict__["_method_name"])
    return fn


def missing_deployment_bounds() -> Dict[str, List[str]]:
    """The unapproved bounds of every container class, by class name."""
    return {name: profile.missing_bounds() for name, profile in PROFILES.items()}


def declared_timeout(profile: ResourceProfile) -> int:
    """The declared execution timeout of a class - refuses when it is unapproved."""
    return int(require(profile.timeout_sec, "timeout_sec", profile.container_class))


def modal_function_kwargs(container_class: str, function_name: str) -> Dict[str, Any]:
    """The decorator keyword arguments of one dispatched function.

    The resource and lifecycle bounds come from the class profile; the network
    blocking declaration comes from the function's egress policy. A bound that is not
    approved is never replaced by a permissive default - it is absent, and the
    absence is reported by :func:`missing_deployment_bounds`.
    """
    kwargs = PROFILES[container_class].modal_kwargs()
    policy = egress_policy(function_name)
    if policy is not None:
        kwargs["block_network"] = policy.block_network
    return kwargs


def _dispatch_through_gate(
    container_class: str, function_name: str, fn: Any, *args: Any, **kwargs: Any
) -> Any:
    """Route a guarded provider call through the single R1 dispatch gate.

    The import is lazy on purpose: the gate lives in the producer's package, and
    the container image of the deployment carries only ``core`` and ``sandbox``.
    The gate is needed on the client side, where the whole repository is
    importable; if it is not, the call is refused instead of dispatched.
    """
    try:
        from benchmarks.r1_dispatch import dispatch_through_gate
    except Exception as exc:  # pragma: no cover - defensive
        raise UnauthorisedCallSite(
            function_name,
            f"the R1 dispatch gate is not importable: {type(exc).__name__}: {exc}",
        ) from exc
    return dispatch_through_gate(container_class, function_name, fn, *args, **kwargs)


class GuardedRemote:
    """A provider callable that fails closed while its bounds are unapproved.

    The wrapper is installed on the module-level name of every dispatched function.
    While a required bound of the function's container class is required-but-unset,
    the call is refused: an unapproved deployment must not be able to start a
    billable container.

    The wrapper is also the **single dispatch path**: a guarded call is routed
    through the R1 gate, so the invocation budget, the concurrency gate, the
    ceiling assertion, the payload cap and the autoscaler read-back apply to it
    exactly as they apply to every other dispatch. A call that bypasses the gate
    is a bypass of the budget.

    The wrapper holds **no reference to the provider object**: the raw Modal
    callable lives in the module-private registry of this module, under an
    opaque token, and the guard hands out its name and its guarded ``remote``
    only. The R1 review named the raw object in the wrapper's own instance
    dictionary (``_fn``) as a bypass of the gate; that attribute does not exist
    any more, and no other attribute of the guard yields the raw callable.
    """

    def __init__(self, fn: Any, function_name: str) -> None:
        self.__dict__["_function_name"] = function_name
        self.__dict__["_object_token"] = _register_guarded_object(fn)
        self.__dict__[PROVIDER_CALLABLE_MARKER] = True

    @property
    def function_name(self) -> str:
        return self.__dict__["_function_name"]

    def substituted_remote(self) -> Optional[Any]:
        """The local double that was substituted on this guard, if any.

        A substituted ``remote`` starts no container and costs nothing, so the
        dispatch contract of a provider call does not apply to it.
        """
        candidate = self.__dict__.get("remote")
        if candidate is None:
            return None
        if getattr(candidate, "__func__", None) is type(self).remote:
            return None
        return candidate

    def r1_reaches_provider(self) -> bool:
        """True when calling ``remote`` would reach the provider.

        A ``remote`` that was substituted on the instance is a local function: it
        starts no container and costs nothing, so the dispatch contract of a
        provider call does not apply to it.
        """
        return self.substituted_remote() is None

    def remote(self, *args: Any, **kwargs: Any) -> Any:
        function_name = self.__dict__["_function_name"]
        assert_dispatch_allowed(function_name)
        container_class = FUNCTION_CLASS[function_name]
        return _dispatch_through_gate(
            container_class,
            function_name,
            _guarded_object(self.__dict__["_object_token"]),
            *args,
            **kwargs,
        )

    def __getattr__(self, item: str) -> Any:
        """No attribute of the guard yields the raw provider callable.

        The raw callable lives in the module-private registry of this module; the
        guard hands out its name, its marker and its guarded ``remote`` - nothing
        else. The underscore-prefixed attributes are refused outright, because
        they are the ones the R1 review named as the bypass (``_fn``).
        """
        if item == "update_autoscaler":
            raise UnauthorisedCallSite(
                self.__dict__["_function_name"],
                "the autoscaler of a guarded function may not be updated from this "
                "repository: the read-back is read-only (D27)",
            )
        if item.startswith("_"):
            raise AttributeError(
                f"the guarded function '{self.__dict__['_function_name']}' exposes no "
                f"attribute '{item}': the guard holds no provider object"
            )
        raise AttributeError(
            f"the guarded function '{self.__dict__['_function_name']}' exposes no "
            f"attribute '{item}': only the guarded 'remote' is handed out"
        )


class GuardedProviderRemote:
    """The guard installed on a provider object's **own** ``remote``.

    This is the boundary installation: the provider object itself carries the
    guard, so every reference to that object - the module-level name, an import
    of it, the object in the private registry - reaches the dispatch gate. A
    caller that gets hold of the raw object does not get an unguarded call.

    The guard holds no reference to the provider object either: it holds the
    call-site name and resolves the object in the private registry when it is
    called.
    """

    def __init__(self, function_name: str) -> None:
        self.__dict__["_function_name"] = function_name
        self.__dict__[PROVIDER_CALLABLE_MARKER] = True

    @property
    def function_name(self) -> str:
        return self.__dict__["_function_name"]

    def r1_reaches_provider(self) -> bool:
        return True

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._dispatch(args, kwargs)

    async def aio(self, *args: Any, **kwargs: Any) -> Any:
        """The asynchronous variant of the guarded call.

        The gate is synchronous, so the dispatch runs in a worker thread: the
        call itself is the same gated call, not a second path.
        """
        import asyncio

        return await asyncio.to_thread(self._dispatch, args, kwargs)

    def _dispatch(self, args: Any, kwargs: Any) -> Any:
        function_name = self.__dict__["_function_name"]
        container_class = FUNCTION_CLASS.get(function_name)
        if container_class is None:
            raise UnauthorisedCallSite(
                function_name,
                "it is not a declared dispatchable function of the "
                "evidence-regeneration workflow",
            )
        fn = _INSTALLED_OBJECTS.get(function_name)
        if fn is None:
            raise UnauthorisedCallSite(
                function_name,
                "the provider object of this call site is not installed",
            )
        return _dispatch_through_gate(container_class, function_name, fn, *args, **kwargs)

    def __getattr__(self, item: str) -> Any:
        if item.startswith("_"):
            raise AttributeError(
                f"the guarded provider remote of "
                f"'{self.__dict__['_function_name']}' exposes no attribute '{item}'"
            )
        raise AttributeError(
            f"the guarded provider remote of "
            f"'{self.__dict__['_function_name']}' exposes no attribute '{item}'"
        )


class GuardedClassMethod:
    """The guard of one method of a Modal class.

    A class method is a provider callable too: the instance's method is a
    ``modal`` function that starts a container. The module-level guard did not
    cover it, so the class-method path was a bypass of the dispatch gate - the
    exact bypass the R1 review named. The guard closes it: the call site is
    checked against the authorised trace, the declared bounds are checked, and the
    call is routed through the same gate as every other dispatch.

    The method object itself is **not** held: it is resolved from the live
    instance at the moment of the call and lives only as a local variable of that
    call. No attribute of the guard yields a raw provider callable.
    """

    def __init__(
        self,
        instance_token: str,
        method_name: str,
        function_name: str,
        class_name: str,
    ) -> None:
        self.__dict__["_instance_token"] = instance_token
        self.__dict__["_method_name"] = method_name
        self.__dict__["_function_name"] = function_name
        self.__dict__["_class_name"] = class_name
        self.__dict__[PROVIDER_CALLABLE_MARKER] = True

    @property
    def function_name(self) -> str:
        return self.__dict__["_function_name"]

    @property
    def class_name(self) -> str:
        return self.__dict__["_class_name"]

    def substituted_remote(self) -> Optional[Any]:
        """The local double that was substituted on this guard, if any."""
        candidate = self.__dict__.get("remote")
        if candidate is None:
            return None
        if getattr(candidate, "__func__", None) is type(self).remote:
            return None
        return candidate

    def r1_reaches_provider(self) -> bool:
        return self.substituted_remote() is None

    def remote(self, *args: Any, **kwargs: Any) -> Any:
        function_name = self.__dict__["_function_name"]
        assert_dispatch_allowed(function_name)
        container_class = FUNCTION_CLASS[function_name]
        instance = _guarded_object(self.__dict__["_instance_token"])
        # The method object is resolved here and nowhere else: it is a local
        # variable of this call, so it cannot be reached afterwards. The
        # resolution goes through the guarded subclass of the instance, so the
        # method it returns carries the guard of its own.
        method = getattr(instance, self.__dict__["_method_name"])
        return _dispatch_through_gate(
            container_class, function_name, method, *args, **kwargs
        )

    def __getattr__(self, item: str) -> Any:
        if item == "update_autoscaler":
            raise UnauthorisedCallSite(
                self.__dict__["_function_name"],
                "the autoscaler of a guarded class method may not be updated from "
                "this repository: the read-back is read-only (D27)",
            )
        if item.startswith("_"):
            raise AttributeError(
                f"the guarded class method '{self.__dict__['_function_name']}' exposes "
                f"no attribute '{item}': the guard holds no provider object"
            )
        raise AttributeError(
            f"the guarded class method '{self.__dict__['_function_name']}' exposes no "
            f"attribute '{item}': only the guarded 'remote' is handed out"
        )


def _guarded_class_getattr(self: Any, name: str) -> Any:
    """The ``__getattr__`` of a guarded class instance.

    The provider SDK produces a **fresh** provider method on every attribute
    access of a class instance (``modal/cls.py:442``), so a guard that covers
    only the method it handed out leaves the next access unguarded - the
    bypass the R1 re-review named. The guard is therefore installed where the
    method is *produced*: a guarded instance hands out the **guard** and never
    the provider method, whoever asks for the method and from wherever.

    The SDK's own resolver stays where the SDK put it: the guard reaches it
    through ``super()`` and never keeps a copy of it.
    """
    attribute = super(type(self), self).__getattr__(name)
    entry = _GUARDED_CLASS_INSTANCES.get(id(self))
    if entry is None:
        return attribute
    remote = getattr(attribute, "remote", None)
    if not callable(remote):
        return attribute
    return GuardedClassMethod(
        entry["token"],
        name,
        f"{entry['class_name']}.{name}",
        entry["class_name"],
    )


def _raw_class_method(instance: Any, name: str) -> Any:
    """The provider method of a guarded instance - the SDK's own resolution.

    This is the gate's path to the provider method of a class: it bypasses the
    guard of the instance deliberately, because the call has to reach the
    provider - but only from inside the gate, which checks the call site, the
    policy, the approval and the bounds first.

    The method is a transient local of the call: it is not stored and not
    handed out.
    """
    method = super(type(instance), instance).__getattr__(name)
    try:
        setattr(method, PROVIDER_CALLABLE_MARKER, True)
    except Exception:  # pragma: no cover - the SDK's function takes attributes
        pass
    return method


def _guarded_subclass(cls: type) -> type:
    """The subclass that carries the guard of a provider class.

    The subclass exists so that the guard is installed on the attribute
    resolution of the instance while the SDK's own resolver stays in the SDK's
    class: the guard never has to hold a copy of it, so there is no registry
    and no closure through which the unguarded resolution could be reached.
    """
    patched = _GUARDED_SUBCLASSES.get(cls)
    if patched is None:
        patched = type(
            f"_R1Guarded{cls.__name__}", (cls,), {"__getattr__": _guarded_class_getattr}
        )
        _GUARDED_SUBCLASSES[cls] = patched
    return patched


class GuardedClassInstance:
    """The guarded instance of a Modal class: every method of it is guarded.

    The instance holds no reference to the raw instance: the raw instance is in
    the private registry under an opaque token. The instance hands out the
    provider methods of the class - as :class:`GuardedClassMethod` objects - and
    nothing else. Every other attribute of the raw instance (the raw class it
    belongs to, its internal function map) is refused, so no raw provider
    callable can be reached through the instance.

    The instance is also moved to a **guarded subclass** of its class
    (:func:`_guarded_subclass`): the provider SDK produces a fresh provider
    method on every attribute access, so the guard has to be installed where
    the method is *produced* - otherwise the method of the raw instance would
    be unguarded.
    """

    def __init__(self, obj: Any, class_name: str) -> None:
        self.__dict__["_class_name"] = class_name
        token = _register_guarded_object(obj)
        self.__dict__["_object_token"] = token
        _GUARDED_CLASS_INSTANCES[id(obj)] = {"token": token, "class_name": class_name}
        try:
            obj.__class__ = _guarded_subclass(type(obj))
        except Exception as exc:
            # Fail closed: without the guarded subclass the provider methods of
            # this instance would not be guarded at their boundary.
            raise RuntimeError(
                f"the guard could not be installed on the instance of "
                f"'{class_name}': {type(exc).__name__}: {exc}"
            ) from exc

    @property
    def class_name(self) -> str:
        return self.__dict__["_class_name"]

    def __getattr__(self, item: str) -> Any:
        if item.startswith("_"):
            raise AttributeError(
                f"the guarded instance of '{self.__dict__['_class_name']}' exposes no "
                f"attribute '{item}': the guard holds no provider object"
            )
        obj = _guarded_object(self.__dict__["_object_token"])
        attribute = getattr(obj, item)
        if isinstance(attribute, GuardedClassMethod):
            return attribute
        remote = getattr(attribute, "remote", None)
        if callable(remote):
            return GuardedClassMethod(
                self.__dict__["_object_token"],
                item,
                f"{self.__dict__['_class_name']}.{item}",
                self.__dict__["_class_name"],
            )
        raise AttributeError(
            f"the guarded instance of '{self.__dict__['_class_name']}' exposes no "
            f"attribute '{item}': only its provider methods are handed out"
        )


class GuardedClass:
    """The guard of a Modal class.

    The wrapper is installed on the module-level name of every deployed class.
    Instantiating it returns a :class:`GuardedClassInstance`, whose methods are
    :class:`GuardedClassMethod` objects: every provider call of a class method
    goes through the R1 gate.

    The wrapper holds no reference to the raw class: the raw class is in the
    private registry under an opaque token, and the underscore-prefixed
    attributes - the ones the R1 review named as the bypass (``_cls``) - are
    refused outright.
    """

    def __init__(self, cls: Any, class_name: str) -> None:
        self.__dict__["_class_name"] = class_name
        self.__dict__["_object_token"] = _register_guarded_object(cls)
        self.__dict__[PROVIDER_CALLABLE_MARKER] = True

    @property
    def class_name(self) -> str:
        return self.__dict__["_class_name"]

    def __call__(self, *args: Any, **kwargs: Any) -> GuardedClassInstance:
        cls = _guarded_object(self.__dict__["_object_token"])
        instance = cls(*args, **kwargs)
        return GuardedClassInstance(instance, self.__dict__["_class_name"])

    def __getattr__(self, item: str) -> Any:
        if item == "update_autoscaler":
            raise UnauthorisedCallSite(
                self.__dict__["_class_name"],
                "the autoscaler of a guarded class may not be updated from this "
                "repository: the read-back is read-only (D27)",
            )
        if item.startswith("_"):
            raise AttributeError(
                f"the guarded class '{self.__dict__['_class_name']}' exposes no "
                f"attribute '{item}': the guard holds no provider object"
            )
        raise AttributeError(
            f"the guarded class '{self.__dict__['_class_name']}' exposes no attribute "
            f"'{item}': only the guarded instantiation is handed out"
        )


def install_provider_guard(function_name: str, fn: Any) -> GuardedRemote:
    """Install the guard on a provider callable and return the guarded name.

    The guard is installed **on the provider object itself**: the object's own
    ``remote`` is replaced by the guard, so every reference to that object is
    gated. The entry point the provider answers on is **not** captured: it
    stays in the provider's own class and is resolved from there at the moment
    of the call, so the repository holds no provider callable at all.

    The installation fails **closed**: if the object declares no entry point,
    or if its ``remote`` cannot be replaced, the deployment is not guarded and
    the error stops the import instead of leaving an unguarded provider
    callable behind.
    """
    if not _declares_entry_point(fn):
        raise RuntimeError(
            f"the provider object of '{function_name}' declares no 'remote' entry "
            "point; the guard cannot be installed on it"
        )
    _INSTALLED_OBJECTS[function_name] = fn
    guard = GuardedProviderRemote(function_name)
    try:
        setattr(fn, "remote", guard)
    except Exception as exc:
        raise RuntimeError(
            f"the guard could not be installed on the provider object of "
            f"'{function_name}': {type(exc).__name__}: {exc}"
        ) from exc
    wrapper = GuardedRemote(fn, function_name)
    register_deployed_function(function_name, wrapper)
    return wrapper


def install_class_guard(class_name: str, cls: Any) -> GuardedClass:
    """Install the guard on a Modal class and return the guarded name."""
    wrapper = GuardedClass(cls, class_name)
    register_deployed_function(class_name, wrapper)
    return wrapper


def assert_dispatch_allowed(function_name: str) -> None:
    """Refuse a provider dispatch while the bounds it relies on are unapproved.

    This is the fail-closed guard at the function boundary: while a required bound of
    the function's container class is not approved, the deployment cannot be used to
    start a billable container. A call site that is not part of the authorised trace
    is refused first, with the reason of the refusal registry.
    """
    container_class = assert_authorised_call_site(function_name)
    profile = PROFILES[container_class]
    missing = profile.missing_bounds()
    if missing:
        raise BoundsNotApproved(missing, function_name)
    policy = egress_policy(function_name)
    if policy is None:
        raise BoundsNotApproved([f"{function_name} has no egress declaration"], function_name)
    if is_unset(policy.payload_cap_bytes) or is_unset(policy.protocol_allowance_bytes):
        raise BoundsNotApproved(
            [f"{function_name} has an unapproved egress bound"], function_name
        )


def declaration_record() -> Dict[str, Any]:
    """The full declaration record of R1 (approval-record material)."""
    return {
        "profiles": {name: profile.to_record() for name, profile in PROFILES.items()},
        "autoscaler": {
            "fields": list(AUTOSCALER_FIELDS),
            "declared": {
                name: declared_autoscaler_settings(profile)
                for name, profile in PROFILES.items()
            },
        },
        "egress": {
            name: {
                "container_class": policy.container_class,
                "payload_cap_bytes": None if is_unset(policy.payload_cap_bytes) else policy.payload_cap_bytes,
                "protocol_allowance_bytes": (
                    None if is_unset(policy.protocol_allowance_bytes) else policy.protocol_allowance_bytes
                ),
                "block_network": policy.block_network,
                "offline": policy.offline,
                "basis": policy.basis,
            }
            for name, policy in EGRESS_POLICIES.items()
        },
        "class_network_policy": {
            container_class: class_network_policy(container_class)
            for container_class in CLASS_CONTAINER_CLASSES
        },
        "ingress": {
            name: {
                "container_class": policy.container_class,
                "ingress_cap_bytes": (
                    None if is_unset(policy.ingress_cap_bytes) else policy.ingress_cap_bytes
                ),
                "basis": policy.basis,
            }
            for name, policy in INGRESS_POLICIES.items()
        },
        "ingress_note": _PROVIDER_INGRESS_NOTE,
        "authorised_call_sites": dict(FUNCTION_CLASS),
        "unauthorised_call_sites": dict(UNAUTHORISED_CALL_SITES),
        "storage_free_allowance": {
            "gib_per_month": STORAGE_FREE_ALLOWANCE_GIB_PER_MONTH,
            "source": STORAGE_FREE_ALLOWANCE_SOURCE,
        },
        "max_trajectory_payload_bytes": (
            None if is_unset(MAX_TRAJECTORY_PAYLOAD_BYTES) else MAX_TRAJECTORY_PAYLOAD_BYTES
        ),
        "pinned_model": {
            "repo_id": PINNED_MODEL.repo_id,
            "revision": PINNED_MODEL.revision,
            "bytes_total": PINNED_MODEL.bytes_total,
            "measured_at": PINNED_MODEL.measured_at,
            "source": PINNED_MODEL.source,
        },
        "missing_bounds": missing_deployment_bounds(),
    }


def declaration_record_json() -> str:
    return json.dumps(declaration_record(), indent=2, sort_keys=True)


__all__ = [
    "AUTOSCALER_FIELDS",
    "BoundsNotApproved",
    "CLASS_CONTAINER_CLASSES",
    "EGRESS_POLICIES",
    "EgressPolicy",
    "FUNCTION_CLASS",
    "GPU_CLASS",
    "GuardedClass",
    "GuardedClassInstance",
    "GuardedClassMethod",
    "GuardedProviderRemote",
    "GuardedRemote",
    "MAX_TRAJECTORY_PAYLOAD_BYTES",
    "OFFLINE_ENV",
    "PINNED_MODEL",
    "PERSISTENCE",
    "PROFILES",
    "ResourceProfile",
    "SANDBOX_CPU",
    "STORAGE_FREE_ALLOWANCE_GIB_PER_MONTH",
    "STORAGE_FREE_ALLOWANCE_SOURCE",
    "UNAUTHORISED_CALL_SITES",
    "UnauthorisedCallSite",
    "Unset",
    "assert_authorised_call_site",
    "assert_dispatch_allowed",
    "assert_payload_within_cap",
    "class_network_policy",
    "declaration_record",
    "declaration_record_json",
    "declared_autoscaler_settings",
    "declared_timeout",
    "deployed_max_containers",
    "egress_policy",
    "ingress_policy",
    "INGRESS_POLICIES",
    "IngressPolicy",
    "is_provider_callable",
    "is_unset",
    "install_class_guard",
    "install_provider_guard",
    "is_installed_call_site",
    "missing_deployment_bounds",
    "modal_function_kwargs",
    "prefetch_ingress_cap_bytes",
    "profile_for",
    "register_deployed_function",
    "require",
    "verify_model_cache_manifest",
]
