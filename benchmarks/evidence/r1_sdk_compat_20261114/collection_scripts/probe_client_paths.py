"""Read-only probe of the Modal SDK 1.5.5 client paths for the D27 read-back.

Every path is executed in its own subprocess with a hard timeout, so a path that
blocks cannot block the probe.  The only RPC any path issues is the read-only
``FunctionGet`` control-plane call for an app that does not exist - the server
answers ``NotFoundError``.  Nothing is deployed, invoked, written or spent.

Usage:
    python probe_client_paths.py            # write sdk_client_paths.json + raw log
    python probe_client_paths.py --path N   # run a single path and print the result

Paths:
    1  the defective repository code: ``await Client.from_env()``
    2  the asynchronous client ``_Client`` inside one event loop
    3  the asynchronous client twice, each in its own event loop
    4  the public synchronous client, the stub coroutine awaited in a fresh loop
    5  the public synchronous client first, then the asynchronous read
    6  the public synchronous client, the stub coroutine on the synchronizer loop
    7  the asynchronous client through ``synchronize_api`` (the shipped fix)
    8  the asynchronous client through ``synchronize_api``, after the public
       synchronous client has been created (the deadlock case of the shipped fix)
    9  the asynchronous client through ``synchronize_api``, called twice
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

APP_NAME = "aegis-rlvr-security"
OBJECT_TAG = "ProductionAuditAgent.*"
TIMEOUT_SEC = 40

HERE = os.path.dirname(os.path.abspath(__file__))
#: The artefacts are written next to the collection scripts, one level up.
OUT_DIR = os.path.dirname(HERE)

PATHS = {
    "1": "the defective repository code: await Client.from_env()",
    "2": "the asynchronous client _Client inside one event loop",
    "3": "the asynchronous client twice, each in its own event loop",
    "4": "the public synchronous client, the stub coroutine awaited in a fresh loop",
    "5": "the public synchronous client first, then the asynchronous read",
    "6": "the public synchronous client, the stub coroutine on the synchronizer loop",
    "7": "the asynchronous client through synchronize_api (the shipped fix)",
    "8": "the asynchronous client through synchronize_api, after the public client exists",
    "9": "the asynchronous client through synchronize_api, called twice",
}

CHILD = r'''
import asyncio
import sys

from modal_proto import api_pb2


def request():
    return api_pb2.FunctionGetRequest(
        app_name="aegis-rlvr-security",
        object_tag="ProductionAuditAgent.*",
        environment_name="main",
        app_version=0,
    )


async def _async_read():
    from modal.client import _Client

    client = await _Client.from_env()
    return await client.stub.FunctionGet(request())


def _sync_api_reader():
    from modal._utils.async_utils import synchronize_api

    @synchronize_api
    async def _function_get(req):
        from modal.client import _Client

        client = await _Client.from_env()
        return await client.stub.FunctionGet(req)

    return _function_get


def path_current():
    from modal.client import Client

    async def _read():
        client = await Client.from_env()
        return await client.stub.FunctionGet(request())

    return asyncio.run(_read())


def path_async_private():
    return asyncio.run(_async_read())


def path_async_private_twice():
    for i in (1, 2):
        try:
            asyncio.run(_async_read())
        except Exception as exc:
            print(f"  call {i}: {type(exc).__name__}: {exc}", flush=True)
    return "done"


def path_public_sync():
    from modal.client import Client

    client = Client.from_env()
    coro = client.stub.FunctionGet(request())
    return asyncio.run(_await(coro))


async def _await(coro):
    return await coro


def path_public_then_async():
    from modal.client import Client

    client = Client.from_env()
    print(f"  public sync client: {type(client).__name__}", flush=True)
    try:
        asyncio.run(_async_read())
    except Exception as exc:
        print(f"  async read: {type(exc).__name__}: {exc}", flush=True)
    return "done"


def path_public_sync_on_synchronizer_loop():
    import asyncio

    from modal._utils.async_utils import synchronizer
    from modal.client import Client

    client = Client.from_env()
    coro = client.stub.FunctionGet(request())
    future = asyncio.run_coroutine_threadsafe(coro, synchronizer._loop)
    return future.result(timeout=30)


def path_sync_api():
    return _sync_api_reader()(request())


def path_sync_api_after_public_client():
    from modal.client import Client

    client = Client.from_env()
    print(f"  public sync client: {type(client).__name__}", flush=True)
    try:
        _sync_api_reader()(request())
    except Exception as exc:
        print(f"  sync_api read: {type(exc).__name__}: {exc}", flush=True)
    return "done"


def path_sync_api_twice():
    reader = _sync_api_reader()
    for i in (1, 2):
        try:
            reader(request())
        except Exception as exc:
            print(f"  call {i}: {type(exc).__name__}: {exc}", flush=True)
    return "done"


PATHS = {
    "1": path_current,
    "2": path_async_private,
    "3": path_async_private_twice,
    "4": path_public_sync,
    "5": path_public_then_async,
    "6": path_public_sync_on_synchronizer_loop,
    "7": path_sync_api,
    "8": path_sync_api_after_public_client,
    "9": path_sync_api_twice,
}

which = sys.argv[1]
try:
    PATHS[which]()
except BaseException as exc:
    print(f"  -> {type(exc).__name__}: {exc}", flush=True)
    sys.exit(2)
print("  -> completed", flush=True)
'''


def run_path(number: str) -> dict:
    """Run one path in its own process and record the verbatim outcome."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        script = os.path.join(tmp, "_child_probe.py")
        with open(script, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(CHILD)
        try:
            completed = subprocess.run(
                [sys.executable, script, number],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SEC,
            )
        except subprocess.TimeoutExpired:
            return {
                "path": number,
                "description": PATHS[number],
                "outcome": "timeout",
                "detail": f"no answer within {TIMEOUT_SEC}s - the path blocks",
                "stdout": "",
                "stderr": "",
            }
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if completed.returncode == 0:
        outcome = "completed"
        detail = stdout.splitlines()[-1] if stdout else ""
    else:
        outcome = "error"
        detail = stdout.splitlines()[-1] if stdout else stderr.splitlines()[-1]
    return {
        "path": number,
        "description": PATHS[number],
        "outcome": outcome,
        "detail": detail,
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--path":
        result = run_path(sys.argv[2])
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    results = [run_path(number) for number in sorted(PATHS)]
    report = {
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "collector": "probe_client_paths.py (read-only Modal SDK 1.5.5 client probe)",
        "modal_client_version": "1.5.5",
        "read_only": True,
        "rpcs_issued": ["FunctionGet (read-only control-plane read)"],
        "app_name": APP_NAME,
        "object_tag": OBJECT_TAG,
        "timeout_sec": TIMEOUT_SEC,
        "note": (
            "the app does not exist, so every path that reaches the control plane "
            "is answered with NotFoundError; a path that blocks instead never "
            "reaches the server"
        ),
        "paths": results,
    }
    with open(os.path.join(OUT_DIR, "sdk_client_paths.json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    lines = []
    for result in results:
        lines.append("=" * 70)
        lines.append(f"PATH {result['path']}: {result['description']}")
        lines.append(f"  outcome: {result['outcome']}")
        lines.append(f"  detail : {result['detail']}")
        if result.get("stdout"):
            lines.append("  stdout :")
            lines.extend(f"    {line}" for line in result["stdout"].splitlines())
        if result.get("stderr"):
            lines.append("  stderr :")
            lines.extend(f"    {line}" for line in result["stderr"].splitlines())
    with open(os.path.join(OUT_DIR, "raw_client_paths.txt"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
