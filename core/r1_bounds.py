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
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

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
        payload_cap_bytes=Unset(
            "the prefetch cap is pinned_bytes x (1 + R_download); neither the retry "
            "count nor the pinned revision's byte size is approved yet (D29)"
        ),
        protocol_allowance_bytes=_PROTOCOL_UNSET,
        block_network=False,
        offline=False,
        basis="the model-cache prefetch of R2p is the only container that downloads "
        "the model; its egress is bounded by the pinned revision (D29)",
    ),
}


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


def prefetch_payload_cap_bytes() -> int:
    """``pinned_bytes x (1 + R_download)`` - the prefetch's per-container payload cap."""
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
    """

    def __init__(self, fn: Any, function_name: str) -> None:
        self.__dict__["_fn"] = fn
        self.__dict__["_function_name"] = function_name
        self.__dict__[PROVIDER_CALLABLE_MARKER] = True

    @property
    def function_name(self) -> str:
        return self.__dict__["_function_name"]

    def r1_reaches_provider(self) -> bool:
        """True when calling ``remote`` would reach the provider.

        A ``remote`` that was substituted on the instance is a local function: it
        starts no container and costs nothing, so the dispatch contract of a
        provider call does not apply to it.
        """
        candidate = self.__dict__.get("remote")
        if candidate is None:
            return True
        return getattr(candidate, "__func__", None) is type(self).remote

    def remote(self, *args: Any, **kwargs: Any) -> Any:
        function_name = self.__dict__["_function_name"]
        assert_dispatch_allowed(function_name)
        container_class = FUNCTION_CLASS[function_name]
        return _dispatch_through_gate(
            container_class, function_name, self.__dict__["_fn"], *args, **kwargs
        )

    def __getattr__(self, item: str) -> Any:
        if item == "update_autoscaler":
            raise UnauthorisedCallSite(
                self.__dict__["_function_name"],
                "the autoscaler of a guarded function may not be updated from this "
                "repository: the read-back is read-only (D27)",
            )
        return getattr(self.__dict__["_fn"], item)


class GuardedClassMethod:
    """The guard of one method of a Modal class.

    A class method is a provider callable too: the instance's method is a
    ``modal`` function that starts a container. The module-level guard did not
    cover it, so the class-method path was a bypass of the dispatch gate - the
    exact bypass the R1 review named. The guard closes it: the call site is
    checked against the authorised trace, the declared bounds are checked, and the
    call is routed through the same gate as every other dispatch.
    """

    def __init__(self, fn: Any, function_name: str, class_name: str) -> None:
        self.__dict__["_fn"] = fn
        self.__dict__["_function_name"] = function_name
        self.__dict__["_class_name"] = class_name
        self.__dict__[PROVIDER_CALLABLE_MARKER] = True

    @property
    def function_name(self) -> str:
        return self.__dict__["_function_name"]

    @property
    def class_name(self) -> str:
        return self.__dict__["_class_name"]

    def r1_reaches_provider(self) -> bool:
        candidate = self.__dict__.get("remote")
        if candidate is None:
            return True
        return getattr(candidate, "__func__", None) is type(self).remote

    def remote(self, *args: Any, **kwargs: Any) -> Any:
        function_name = self.__dict__["_function_name"]
        assert_dispatch_allowed(function_name)
        container_class = FUNCTION_CLASS[function_name]
        return _dispatch_through_gate(
            container_class, function_name, self.__dict__["_fn"], *args, **kwargs
        )

    def __getattr__(self, item: str) -> Any:
        if item == "update_autoscaler":
            raise UnauthorisedCallSite(
                self.__dict__["_function_name"],
                "the autoscaler of a guarded class method may not be updated from "
                "this repository: the read-back is read-only (D27)",
            )
        return getattr(self.__dict__["_fn"], item)


class GuardedClassInstance:
    """The guarded instance of a Modal class: every method of it is guarded."""

    def __init__(self, obj: Any, class_name: str) -> None:
        self.__dict__["_obj"] = obj
        self.__dict__["_class_name"] = class_name

    def __getattr__(self, item: str) -> Any:
        attribute = getattr(self.__dict__["_obj"], item)
        remote = getattr(attribute, "remote", None)
        if callable(remote):
            return GuardedClassMethod(
                attribute,
                f"{self.__dict__['_class_name']}.{item}",
                self.__dict__["_class_name"],
            )
        return attribute


class GuardedClass:
    """The guard of a Modal class.

    The wrapper is installed on the module-level name of every deployed class.
    Instantiating it returns a :class:`GuardedClassInstance`, whose methods are
    :class:`GuardedClassMethod` objects: every provider call of a class method
    goes through the R1 gate.
    """

    def __init__(self, cls: Any, class_name: str) -> None:
        self.__dict__["_cls"] = cls
        self.__dict__["_class_name"] = class_name
        self.__dict__[PROVIDER_CALLABLE_MARKER] = True

    @property
    def class_name(self) -> str:
        return self.__dict__["_class_name"]

    def __call__(self, *args: Any, **kwargs: Any) -> GuardedClassInstance:
        instance = self.__dict__["_cls"](*args, **kwargs)
        return GuardedClassInstance(instance, self.__dict__["_class_name"])

    def __getattr__(self, item: str) -> Any:
        if item == "update_autoscaler":
            raise UnauthorisedCallSite(
                self.__dict__["_class_name"],
                "the autoscaler of a guarded class may not be updated from this "
                "repository: the read-back is read-only (D27)",
            )
        return getattr(self.__dict__["_cls"], item)


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
    "is_provider_callable",
    "is_unset",
    "missing_deployment_bounds",
    "modal_function_kwargs",
    "prefetch_payload_cap_bytes",
    "profile_for",
    "register_deployed_function",
    "require",
    "verify_model_cache_manifest",
]
