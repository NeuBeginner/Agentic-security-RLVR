"""
benchmarks/modal_cpu_smoke_app.py
=================================

The separate, minimal, **CPU-only** Modal app of the Iteration 19 runtime smoke
test.

This app is not a production worker and it is not part of the benchmark run. It
exists for exactly one reason: to prove that a **real** Modal worker is reached
and reports its **own** runtime identity, instead of another offline rehearsal
or a local mock.

Its surface is deliberately tiny:

* one app, one function, one invocation;
* ``gpu=None`` - no GPU is requested, so none can be allocated;
* ``cpu=0.5``, ``memory=256`` (MiB) - a minimal footprint;
* ``timeout=60`` seconds, ``retries=0`` - bounded, no retry loop;
* no model, no secret, no volume, no persistent storage, no network access;
* it never imports ``modal_app.py``, never instantiates a production class and
  never calls a GPU-backed method.

The image is ``debian_slim`` plus **one** mounted file: the repository's own
``benchmarks/evidence_integrity.py``. The worker therefore builds the
runtime-identity envelope with exactly the primitives that the validator later
checks - there is no second, drifting implementation of the contract.

Every fact the worker reports is observed **inside the running container**:

===============================  ==========================================
fact                             source
===============================  ==========================================
``function_call_id``             ``modal.current_function_call_id()``
``input id``                     ``modal.current_input_id()``
``container id``                 ``MODAL_WORKER_ID`` (fallback ``HOSTNAME``)
``image_id``                     ``MODAL_IMAGE_ID`` of the running container
Python / OS / Modal SDK version   observed in the container
GPU evidence                     observed in the container
===============================  ==========================================

A fact that cannot be observed is recorded as an explicit ``NOT_AVAILABLE``
with the reason - never as a constant, a guess or a template. Modal SDK 1.5.5
offers no running-app accessor to a function container, so the app id and the
container id of the run are taken from the provider on the client side
(``App.app_id`` and the provider's container list); the worker states its own
side of that honestly.
"""

from __future__ import annotations

import glob
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

import modal

# The repository root - the mount below is resolved against it, so the worker
# runs the *current* evidence module of this checkout.
_ROOT = Path(__file__).resolve().parent.parent

#: The one file that is mounted into the image: the evidence module of the
#: repository. It is a pure-stdlib module, so it imports unchanged in the
#: container.
_EVIDENCE_MODULE_LOCAL = _ROOT / "benchmarks" / "evidence_integrity.py"
_EVIDENCE_MODULE_REMOTE = "/root/evidence_integrity.py"

image = (
    modal.Image.debian_slim(python_version="3.11")
    .add_local_file(str(_EVIDENCE_MODULE_LOCAL), _EVIDENCE_MODULE_REMOTE)
)

app = modal.App("aegis-iteration19-cpu-smoke", image=image)

#: The declared resources of the smoke function - one source of truth, so the
#: driver reports exactly what the source declares instead of a copy of it.
DECLARED_RESOURCES: Dict[str, Any] = {
    "gpu": None,
    "cpu": 0.5,
    "memory": 256,
    "timeout": 60,
    "retries": 0,
}


# ---------------------------------------------------------------------------
# The worker
# ---------------------------------------------------------------------------

def _gpu_evidence() -> Dict[str, Any]:
    """
    Collect the GPU facts the container can actually observe.

    An empty result is the evidence that no GPU was attached to this
    container: no CUDA devices are exposed, no NVIDIA device nodes exist, no
    CUDA runtime library is installed and no driver tooling is on the PATH.
    """
    nvidia_nodes: List[str] = []
    try:
        nvidia_nodes = sorted(name for name in os.listdir("/dev") if name.startswith("nvidia"))
    except OSError:
        nvidia_nodes = []

    cuda_libraries: List[str] = []
    for pattern in ("/usr/local/lib/libcudart*", "/usr/lib/x86_64-linux-gnu/libcudart*"):
        cuda_libraries.extend(sorted(glob.glob(pattern)))

    return {
        "nvidia_visible_devices_env": os.environ.get("NVIDIA_VISIBLE_DEVICES"),
        "cuda_visible_devices_env": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "nvidia_device_nodes": nvidia_nodes,
        "nvidia_smi_on_path": shutil.which("nvidia-smi"),
        "cuda_runtime_libraries": cuda_libraries,
        "gpu_device_exposed": bool(nvidia_nodes),
    }


def _capture_runtime_identity(ei: Any, modal_module: Any) -> Dict[str, Any]:
    """
    Build the runtime-identity envelope of the running container.

    Only the runtime-context APIs that the installed Modal SDK really offers
    are used:

    * ``modal.current_function_call_id()`` - the id of the current call;
    * ``modal.current_input_id()`` - the id of the current input;
    * ``modal.is_local()`` - ``False`` inside a Modal container;
    * the ``MODAL_IMAGE_ID`` environment variable - the image of the container.

    Modal SDK 1.5.5 offers **no** running-app accessor to a function
    container (``modal.running_app`` is a module, not a callable), and it sets
    neither ``MODAL_WORKER_ID`` nor ``HOSTNAME`` in a function container. The
    app id and the container id of this run are therefore taken from the
    provider on the client side; the worker states that honestly instead of
    inventing a value.
    """
    identity: Dict[str, Any] = {}

    identity["app_id"] = ei.not_available(
        "Modal SDK 1.5.5 exposes no running-app accessor to a function container: "
        "modal.running_app is a module and not a callable, and the runtime-context API "
        "(modal.current_function_call_id, modal.current_input_id, modal.interact, "
        "modal.is_local) carries no application id. The app id of this run is taken "
        "from the provider-issued App.app_id on the client side instead."
    )

    function_call_id = None
    try:
        function_call_id = modal_module.current_function_call_id()
    except Exception:
        function_call_id = None

    identity["function_call_id"] = (
        ei.observed(str(function_call_id), source="modal.current_function_call_id()")
        if function_call_id
        else ei.not_available(
            "the Modal runtime did not expose a function-call id inside this container"
        )
    )

    container_id = os.environ.get("MODAL_WORKER_ID") or os.environ.get("HOSTNAME")
    identity["container_id"] = (
        ei.observed(str(container_id), source="MODAL_WORKER_ID/HOSTNAME of the running container")
        if container_id
        else ei.not_available(
            "the running container exposed neither MODAL_WORKER_ID (the SDK reads it from "
            "the 'worker_id' configuration setting, which the runtime sets only for "
            "internal debugging) nor HOSTNAME (this container sets no hostname), so the "
            "worker itself could not attest its container identity; the container id of "
            "this run is taken from the provider's container list on the client side "
            "instead"
        )
    )

    # The immutable image identity of the running container. The Modal SDK
    # exposes it as the ``image_id`` configuration setting, which the runtime
    # publishes as ``MODAL_IMAGE_ID`` inside the container.
    image_id = os.environ.get("MODAL_IMAGE_ID")
    identity["image_id"] = (
        ei.observed(str(image_id), source="MODAL_IMAGE_ID of the running container")
        if image_id
        else ei.not_available(
            "the running container did not expose MODAL_IMAGE_ID, so the identity of the "
            "image it runs on cannot be attested"
        )
    )

    return identity


@app.function(
    # No GPU: the request is explicit, so none can be allocated.
    gpu=DECLARED_RESOURCES["gpu"],
    cpu=DECLARED_RESOURCES["cpu"],
    memory=DECLARED_RESOURCES["memory"],
    timeout=DECLARED_RESOURCES["timeout"],
    retries=DECLARED_RESOURCES["retries"],
)
def cpu_smoke(seed: str) -> Dict[str, Any]:
    """
    Return a small deterministic payload and the runtime-identity envelope.

    The payload is deterministic for a given seed, so the artifact can be
    compared byte by byte; the envelope holds what the container observed
    about itself.
    """
    if str(Path(_EVIDENCE_MODULE_REMOTE).parent) not in sys.path:
        sys.path.insert(0, str(Path(_EVIDENCE_MODULE_REMOTE).parent))
    import evidence_integrity as ei  # noqa: E402  (the mounted repository module)

    runtime_identity = _capture_runtime_identity(ei, modal)

    payload = {
        "smoke_result": "ok",
        "seed": seed,
        "echo": f"iteration19-cpu-smoke:{seed}",
        "deterministic_sha256": ei.sha256_text(f"iteration19-cpu-smoke:{seed}"),
    }

    worker_observed: Dict[str, Any] = {
        "python_version": sys.version,
        "python_version_info": list(sys.version_info[:3]),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "os_name": os.name,
        "platform": platform.platform(),
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "platform_machine": platform.machine(),
        "kernel_release": platform.uname().release,
        "cpu_count": os.cpu_count(),
        "hostname": os.environ.get("HOSTNAME"),
        "modal_sdk_version": getattr(modal, "__version__", None),
        "modal_environment": os.environ.get("MODAL_ENVIRONMENT"),
        "modal_image_id_env": os.environ.get("MODAL_IMAGE_ID"),
        "modal_worker_id_env": os.environ.get("MODAL_WORKER_ID"),
        "modal_env_var_names": sorted(
            name for name in os.environ if name.startswith("MODAL_")
        ),
        # ``is_local()`` is False inside a Modal container and True everywhere
        # else - the runtime's own statement that this is not a local process.
        "modal_is_local": modal.is_local(),
        "modal_current_input_id": modal.current_input_id(),
        "working_directory": os.getcwd(),
        "gpu_evidence": _gpu_evidence(),
    }

    return {
        "smoke_payload": payload,
        # The runtime-identity envelope is carried by the response at this
        # source - the binding the Iteration 18 contract enforces.
        "modal_runtime": runtime_identity,
        "worker_observed": worker_observed,
    }
