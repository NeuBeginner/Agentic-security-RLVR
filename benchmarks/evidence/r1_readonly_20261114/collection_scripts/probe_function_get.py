"""Minimal read-only FunctionGet probe (Modal SDK 1.5.5, async _Client path)."""

import asyncio
import json
import sys

from modal.client import _Client
from modal_proto import api_pb2

APP_NAME = "aegis-rlvr-security"
OBJECT_TAG = "ProductionAuditAgent.*"


async def main():
    request = api_pb2.FunctionGetRequest(
        app_name=APP_NAME,
        object_tag=OBJECT_TAG,
        environment_name="main",
        app_version=0,
    )
    client = await _Client.from_env()
    try:
        response = await asyncio.wait_for(
            client.stub.FunctionGet(request), timeout=60
        )
        return {"ok": True, "response": response}
    finally:
        await client._close()


if __name__ == "__main__":
    try:
        out = asyncio.run(main())
        resp = out["response"]
        info = {
            "has_function": bool(resp.HasField("function")),
            "raw_type": str(type(resp)),
        }
        if resp.HasField("function"):
            fn = resp.function
            info["autoscaler_settings_present"] = bool(fn.HasField("autoscaler_settings"))
            s = fn.autoscaler_settings
            info["fields"] = {
                name: {
                    "present": bool(s.HasField(name)),
                    "value": int(getattr(s, name, 0)) if s.HasField(name) else None,
                }
                for name in ("min_containers", "max_containers", "buffer_containers",
                             "scaledown_window")
            }
        print(json.dumps(info, indent=2))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        sys.exit(0)
