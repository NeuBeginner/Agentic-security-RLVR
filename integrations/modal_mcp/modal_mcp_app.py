"""
integrations/modal_mcp/modal_mcp_app.py
=======================================

The deployment of the Modal MCP server.

The application is CPU-only. It declares no GPU, it has no secret of its own
besides the dedicated Modal credential, and it mounts the results volume of
the audit service read-only, so that it can list the stored runs without being
able to change them.

The endpoint has a stable label, so that the public URL does not change from
one deployment to the next::

    https://<workspace>--modal-mcp.modal.run/mcp

The credential of the server arrives through the Modal Secret
``modal-mcp-credentials``; it never appears in the image, in the code or in a
log record.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import modal

def _repository_root() -> Path:
    """
    The root of the sources of the server.

    While the application is deployed, this module is the entrypoint of the
    image and it is copied to ``/root``, while the package ``integrations`` is
    installed into ``site-packages``. The root therefore cannot be derived from
    the path of this file alone: the installed package is the authority.
    """
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "integrations" / "modal_mcp").is_dir():
            return candidate
    try:
        import integrations

        return Path(integrations.__file__).resolve().parent.parent
    except Exception:  # pragma: no cover - the package is always installed
        return here.parent


_ROOT = _repository_root()
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from integrations.modal_mcp.config import Settings  # noqa: E402
from integrations.modal_mcp.modal_access import ModalAccess  # noqa: E402
from integrations.modal_mcp.policy import Policy, audit  # noqa: E402
from integrations.modal_mcp.server import build_app  # noqa: E402
from integrations.modal_mcp.state import ModalDictStateStore  # noqa: E402

#: The name of the application of the server.
APP_NAME = "aegis-modal-mcp"

#: The label of the web endpoint. It is part of the public URL, so it is
#: fixed: ``https://<workspace>--modal-mcp.modal.run``.
ENDPOINT_LABEL = "modal-mcp"

#: The Modal Secret that holds the dedicated credential of the server.
CREDENTIALS_SECRET_NAME = "modal-mcp-credentials"

#: The repository-owned sources of the targets and the candidate registry.
TARGETS_LOCAL = _ROOT / "benchmarks" / "targets" / "solidity"
POCS_LOCAL = _ROOT / "benchmarks" / "cpu_audit_pocs"

#: The declared resources of the server. The request for a GPU is explicit:
#: ``gpu=None``. The server cannot allocate an accelerator, not even by
#: accident.
DECLARED_RESOURCES = {
    "gpu": None,
    "cpu": 1.0,
    "memory": 1024,
    "timeout": 300,
    "min_containers": 0,
    "max_containers": 4,
}

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("mcp>=1.2,<2", "modal>=1.5,<2", "pydantic>=2")
    .add_local_python_source("integrations", copy=True)
    # The package ``core`` carries the models of the CPU audit service. The
    # client of a remote call has to be able to import them, otherwise the
    # answer of the service cannot be deserialised ("the 'core' module is not
    # available in the remote environment").
    .add_local_python_source("core", copy=True)
    .add_local_dir(str(TARGETS_LOCAL), remote_path="/opt/aegis/targets/solidity", copy=True)
    .add_local_dir(str(POCS_LOCAL), remote_path="/opt/aegis/cpu_audit_pocs", copy=True)
)

#: The public URL of the server, if it was configured at deploy time. It is
#: the issuer of the OAuth authorization server; without it the issuer is
#: derived from the host of the request, which is the host of the deployment
#: anyway.
ISSUER = os.environ.get("MODAL_MCP_ISSUER", "").strip()
if ISSUER:
    image = image.env({"MODAL_MCP_ISSUER": ISSUER})

app = modal.App(APP_NAME, image=image)


@app.function(
    image=image,
    secrets=[modal.Secret.from_name(CREDENTIALS_SECRET_NAME)],
    **DECLARED_RESOURCES,
)
@modal.asgi_app(label=ENDPOINT_LABEL)
def server() -> Any:
    """Build the ASGI application of the MCP server."""
    settings = Settings.from_env()
    if not settings.has_modal_credentials:
        # Fail closed: without the dedicated credential the server refuses to
        # start rather than falling back to an ambient credential.
        raise RuntimeError(
            "the dedicated Modal credential is missing: the secret "
            f"{CREDENTIALS_SECRET_NAME} has to carry MODAL_MCP_TOKEN_ID and "
            "MODAL_MCP_TOKEN_SECRET"
        )
    if not settings.access_token:
        raise RuntimeError(
            "the access token of the owner is missing: the secret "
            f"{CREDENTIALS_SECRET_NAME} has to carry MODAL_MCP_ACCESS_TOKEN"
        )

    policy = Policy(settings)
    access = ModalAccess(
        settings.modal_token_id,
        settings.modal_token_secret,
        environment=settings.allowed_environments[0],
        cpu_audit_token=settings.cpu_audit_token,
    )
    state = ModalDictStateStore(settings.state_dict, client=access.client)

    audit(
        "server_started",
        app=APP_NAME,
        environment=settings.allowed_environments[0],
        allowed_apps=list(settings.allowed_apps),
        write_enabled=settings.write_enabled,
    )
    return build_app(settings, policy, access, state)


@app.function(image=image, **DECLARED_RESOURCES)
def describe_configuration() -> dict:
    """The configuration of the server, without a secret."""
    return Settings.from_env().public_view()


if __name__ == "__main__":
    modal.run(app)
