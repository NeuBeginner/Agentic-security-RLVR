"""Read-only autoscaler read-back for the deployed 'ProductionAuditAgent.*' function.

Uses the provider's read-only ``FunctionGet`` RPC only - the same RPC the
repository's own reader (benchmarks.r1_dispatch.provider_autoscaler_reader) uses.
No deployment, no update_autoscaler(), no function invocation, no dispatch.
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone

REPO = r"D:\Install\I\Dropbox\Coding\GitHub\Agentic-security-RLVR"
sys.path.insert(0, REPO)

APP_NAME = "aegis-rlvr-security"
OBJECT_TAG = "ProductionAuditAgent.*"
ENVIRONMENT = "main"

REDACT_KEYS = ("token", "secret", "password", "key", "credential", "authorization")
SENSITIVE = ("token", "secret", "password", "credential")


def redact(value, depth=0):
    """Redact anything that looks like a credential from the raw response."""
    if depth > 12:
        return "<truncated>"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if any(s in str(k).lower() for s in SENSITIVE):
                out[k] = "<redacted>"
            else:
                out[k] = redact(v, depth + 1)
        return out
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value]
    if isinstance(value, str):
        low = value.lower()
        if any(s in low for s in ("token", "secret")) and len(value) > 12:
            return "<redacted>"
        return value
    return value


def main():
    os.environ["R1_ENABLE_PROVIDER_READBACK"] = "1"
    from benchmarks import r1_dispatch

    result = {
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "app_name": APP_NAME,
        "object_tag": OBJECT_TAG,
        "environment": ENVIRONMENT,
        "rpc": "FunctionGet (read-only)",
        "repository_reader": "benchmarks.r1_dispatch.provider_autoscaler_reader",
    }

    # --- 1. the repository's own reader ---------------------------------------
    class _Target:
        _app = type("_App", (), {"name": APP_NAME})()
        _tag_ = OBJECT_TAG

    try:
        settings = r1_dispatch.provider_autoscaler_reader(
            _Target(), "ProductionAuditAgent.generate_solidity_exploit"
        )
        result["reader_status"] = "VERIFIED"
        result["reader_result"] = settings
    except Exception as exc:
        result["reader_status"] = "UNAVAILABLE"
        result["reader_error"] = f"{type(exc).__name__}: {exc}"

    # --- 2. the raw provider response ------------------------------------------
    try:
        from modal.client import Client
        from modal_proto import api_pb2

        request = api_pb2.FunctionGetRequest(
            app_name=APP_NAME,
            object_tag=OBJECT_TAG,
            environment_name=ENVIRONMENT,
            app_version=0,
        )

        # Modal SDK 1.5.5 defines ``Client = synchronize_api(_Client)``
        # (modal/client.py:532): the public client is SYNCHRONOUS.  The underlying
        # async client is used directly, inside one event loop, so the gRPC channel
        # is bound to that loop.
        from modal.client import _Client

        async def _read():
            client = await _Client.from_env()
            try:
                return await asyncio.wait_for(
                    client.stub.FunctionGet(request), timeout=60
                )
            finally:
                await client._close()

        response = asyncio.run(_read())

        raw = {}
        raw["has_function_submessage"] = bool(
            hasattr(response, "HasField") and response.HasField("function")
        )
        fn = getattr(response, "function", None)
        raw["function_present"] = fn is not None
        if fn is not None:
            raw["has_autoscaler_settings"] = bool(
                hasattr(fn, "HasField") and fn.HasField("autoscaler_settings")
            )
            settings = getattr(fn, "autoscaler_settings", None)
            raw["autoscaler_settings_present"] = settings is not None
            if settings is not None:
                fields = {}
                for name in ("min_containers", "max_containers", "buffer_containers",
                             "scaledown_window"):
                    present = bool(
                        hasattr(settings, "HasField") and settings.HasField(name)
                    )
                    fields[name] = {
                        "present": present,
                        "value": int(getattr(settings, name, 0)) if present else None,
                    }
                raw["autoscaler_fields"] = fields
            raw["function_fields_present"] = {
                name: bool(getattr(fn, "HasField") and fn.HasField(name))
                for name in ("function_id", "created_at", "description", "image_id",
                             "app_id", "environment_name")
                if hasattr(fn, "HasField")
            }
        result["raw_response"] = redact(raw)
        result["raw_status"] = "VERIFIED"
    except Exception as exc:
        result["raw_status"] = "UNAVAILABLE"
        result["raw_error"] = f"{type(exc).__name__}: {exc}"

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(out_dir, "autoscaler_readback.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    sys.exit(main())
