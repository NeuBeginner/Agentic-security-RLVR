"""
modal_mcp.tools
===============

The tools of the Modal MCP server.

Every tool is a *named operation* - there is no tool that runs an arbitrary
command, and there is no tool that reads an arbitrary path. The tools are
grouped in three families:

* **diagnostics** - read-only: the state of the workspace, the applications,
  the functions, the logs and the billing;
* **the project** - the CPU audit of this repository: running it, reading its
  evidence, probing its environment and running the allowed smoke tests;
* **management** - the write operations. They exist, but they are switched off
  by default and they need the confirmation value of the owner.

Every tool returns a dictionary. A refusal is a dictionary too: it names the
rule that refused the request, so that a chat client can explain itself.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import time
from typing import Any, Callable, Dict, List, Optional

from mcp.types import ToolAnnotations

from .config import Settings
from .context import get_principal, get_request_id
from .modal_access import AccessError, ModalAccess
from .policy import Policy, PolicyError, audit, request_fingerprint
from .state import StateStore

#: The annotations of a read-only tool: it changes nothing.
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)

#: The annotations of a tool that starts work: it creates artifacts and it
#: consumes compute, but it changes no configuration.
EXECUTES = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False)

#: The annotations of a tool that changes the state of the workspace.
MUTATES = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True)

#: The smoke tests that ``modal_run_tests`` may run. There is no way to run
#: anything else: the suite is a name out of this list.
ALLOWED_TEST_SUITES = ("probe", "evidence_readback", "candidate_registry")


def _cap_result_bytes(payload: Dict[str, Any], max_bytes: int) -> Dict[str, Any]:
    """Enforce ``max_result_bytes`` on a tool result dictionary."""
    if max_bytes <= 0:
        return payload
    encoded = json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")
    if len(encoded) <= max_bytes:
        return payload
    if isinstance(payload.get("entries"), list):
        trimmed = dict(payload)
        entries = list(payload["entries"])
        while entries:
            entries.pop()
            trimmed["entries"] = entries
            trimmed["count"] = len(entries)
            trimmed["truncated"] = True
            trimmed["max_result_bytes"] = max_bytes
            if len(json.dumps(trimmed, default=str, ensure_ascii=False).encode("utf-8")) <= max_bytes:
                return trimmed
    summary: Dict[str, Any] = {
        "status": payload.get("status", "OK"),
        "truncated": True,
        "max_result_bytes": max_bytes,
        "original_bytes": len(encoded),
    }
    if len(json.dumps(summary, default=str, ensure_ascii=False).encode("utf-8")) <= max_bytes:
        return summary
    return {"status": "OK", "truncated": True}


def _ok(
    payload: Dict[str, Any],
    tool: str,
    started: float,
    *,
    max_bytes: int = 0,
) -> Dict[str, Any]:
    """Wrap a successful result with the journal record of the call."""
    bounded = _cap_result_bytes(payload, max_bytes) if max_bytes > 0 else payload
    audit(
        "tool_call",
        tool=tool,
        outcome="ok",
        principal=get_principal(),
        request_id=get_request_id(),
        duration_ms=round((time.time() - started) * 1000, 1),
    )
    return bounded


def _refusal(error: PolicyError, tool: str, started: float) -> Dict[str, Any]:
    """Wrap a refusal with the journal record of the call."""
    audit(
        "tool_call",
        tool=tool,
        outcome="refused",
        code=error.code,
        principal=get_principal(),
        request_id=get_request_id(),
        duration_ms=round((time.time() - started) * 1000, 1),
    )
    return error.to_dict()


class ToolBox:
    """
    The tools of the server.

    The class holds the policy, the access layer and the state, and builds the
    MCP server with the tools registered on it.
    """

    def __init__(
        self,
        settings: Settings,
        policy: Policy,
        access: ModalAccess,
        state: StateStore,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.access = access
        self.state = state

    # -- helpers -------------------------------------------------------------

    def _primary_app(self) -> str:
        """Return the allowlisted CPU audit app, or fail closed."""
        if not self.settings.allowed_apps:
            raise PolicyError(
                "APP_NOT_ALLOWED",
                "no CPU-only application is on the allowlist of this server",
            )
        return self.settings.allowed_apps[0]

    def _enforce_rate_limit(
        self,
        bucket: str,
        limit: int,
        window_sec: int,
        code: str = "RATE_LIMIT_EXCEEDED",
    ) -> None:
        """Enforce a fixed-window counter in the shared state store."""
        if limit <= 0:
            return
        window = int(time.time() // window_sec)
        key = f"ratelimit:{bucket}:{window}"
        record = self.state.get_json(key) or {}
        count = int(record.get("count", 0))
        if count >= limit:
            raise PolicyError(
                code,
                f"rate limit exceeded for {bucket} ({limit} per {window_sec}s)",
                bucket=bucket,
                limit=limit,
                window_sec=window_sec,
            )
        self.state.put_json(key, {"count": count + 1}, ttl_sec=window_sec + 60)

    def _call_with_timeout(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute a blocking access call under ``settings.tool_timeout_sec``."""
        timeout = float(self.settings.tool_timeout_sec)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(fn, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            executor.shutdown(wait=False, cancel_futures=True)
            raise AccessError(
                "TOOL_TIMEOUT",
                f"the tool call exceeded the {self.settings.tool_timeout_sec}s limit",
                timeout_sec=self.settings.tool_timeout_sec,
            ) from exc
        finally:
            executor.shutdown(wait=False)

    def _replay_guard(self, tool: str, request_id: str, arguments: Dict[str, Any]) -> None:
        """Refuse a request that was already seen.

        Two ledgers are kept: one on the fingerprint of the request (the same
        request twice is a replay) and one on the identifier of the request
        (the same identifier with different arguments is an attempt to smuggle
        a second call through).
        """
        self.policy.check_request_id(request_id)
        fingerprint = request_fingerprint(tool, arguments)

        by_request = self.state.get_json(f"replay:id:{request_id}")
        if by_request is not None:
            if by_request.get("fingerprint") != fingerprint:
                raise PolicyError(
                    "REQUEST_ID_REUSED",
                    "the request identifier was already used for a different request",
                    request_id=request_id,
                )
            raise PolicyError(
                "REPLAY_DETECTED",
                "the request was already executed with this identifier",
                request_id=request_id,
            )

        by_fingerprint = self.state.get_json(f"replay:fp:{fingerprint}")
        if by_fingerprint is not None:
            raise PolicyError(
                "REPLAY_DETECTED",
                "the request was already executed with this identifier",
                request_id=request_id,
            )

        self.state.put_json(
            f"replay:id:{request_id}",
            {"fingerprint": fingerprint, "tool": tool, "at": time.time()},
            ttl_sec=86_400,
        )
        self.state.put_json(
            f"replay:fp:{fingerprint}",
            {"request_id": request_id, "tool": tool, "at": time.time()},
            ttl_sec=86_400,
        )

    def _target_source(self, target_name: str) -> Optional[str]:
        """
        Read the source of a target from the mounted, repository-owned copy.

        The control variants of the targets live in the ``controls``
        subdirectory; the source of the target and the harness of the target
        have to exist, otherwise the target is refused: without an immutable
        harness no verdict could be trusted for it.
        """
        if not target_name or not target_name.replace("_", "").isalnum():
            return None
        harness = os.path.join(self.settings.targets_dir, f"{target_name}Harness.t.sol")
        if not os.path.isfile(harness):
            return None
        for relative in (f"{target_name}.sol", os.path.join("controls", f"{target_name}.sol")):
            path = os.path.join(self.settings.targets_dir, relative)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    return handle.read()
            except OSError:
                return None
        return None

    def _allowed_targets(self) -> List[str]:
        """The targets that have a trusted harness in the mounted copy."""
        directory = self.settings.targets_dir
        if not os.path.isdir(directory):
            return []
        names = []
        for entry in sorted(os.listdir(directory)):
            if entry.endswith("Harness.t.sol"):
                names.append(entry[: -len("Harness.t.sol")])
        return names

    # -- the diagnostics -----------------------------------------------------

    def modal_status(self, environment: Optional[str] = None) -> Dict[str, Any]:
        """The state of the workspace and of the environment of the server.

        The tool answers the question "what does this server see?": the
        environment it works in, the applications it may use, the state of the
        CPU audit application and the switch positions of the server. It never
        returns a credential.
        """
        started = time.time()
        try:
            env = environment or self.settings.allowed_environments[0]
            self.policy.check_environment(env)
            apps = self.access.list_apps(environment=env)
            states = []
            for app in apps:
                if app["name"] in self.settings.allowed_apps:
                    states.append(
                        {
                            "name": app["name"],
                            "app_id": app["app_id"],
                            "state": app["state"],
                            "running_tasks": app["running_tasks"],
                            "allowlisted": True,
                        }
                    )
            payload = {
                "status": "OK",
                "environment": env,
                "server": self.settings.public_view(),
                "applications": states,
                "application_count": len(states),
                "allowed_targets": self._allowed_targets(),
            }
            return _ok(payload, "modal_status", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_status", started)

    def modal_list_apps(self) -> Dict[str, Any]:
        """The allowlisted applications of the environment of the server.

        Only applications on the server's allowlist are returned - non-allowlisted
        workspace applications are filtered out.
        """
        started = time.time()
        try:
            env = self.settings.allowed_environments[0]
            apps = self.access.list_apps(environment=env)
            allowlisted = [app for app in apps if app["name"] in self.settings.allowed_apps]
            payload = {
                "status": "OK",
                "environment": env,
                "applications": [
                    {
                        "name": app["name"],
                        "app_id": app["app_id"],
                        "state": app["state"],
                        "running_tasks": app["running_tasks"],
                        "created_at": app["created_at"],
                        "allowlisted": True,
                    }
                    for app in allowlisted
                ],
            }
            return _ok(payload, "modal_list_apps", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_list_apps", started)

    def modal_app_status(self, app: str) -> Dict[str, Any]:
        """The state of one application."""
        started = time.time()
        try:
            self.policy.check_app(app)
            payload = {"status": "OK", "application": self.access.app_status(app)}
            return _ok(payload, "modal_app_status", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_app_status", started)

    def modal_function_status(self, app: str, function: str) -> Dict[str, Any]:
        """The state of one function of one application.

        The answer states the resources of the function - and in particular
        that its GPU is ``None``, which is the proof that the CPU audit
        service cannot allocate an accelerator.
        """
        started = time.time()
        try:
            self.policy.check_function(app, function)
            payload = {
                "status": "OK",
                "function": self.access.function_status(app, function),
            }
            return _ok(payload, "modal_function_status", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_function_status", started)

    def modal_logs(self, app: str, limit: int = 50) -> Dict[str, Any]:
        """The last log entries of one application."""
        started = time.time()
        try:
            self.policy.check_app(app)
            entries = self.access.logs(app, limit=limit)
            payload = {
                "status": "OK",
                "app": app,
                "count": len(entries),
                "entries": entries,
            }
            return _ok(payload, "modal_logs", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_logs", started)

    def modal_billing(self) -> Dict[str, Any]:
        """The billing summary of the workspace for the current month."""
        started = time.time()
        try:
            payload = {"status": "OK", "billing": self.access.billing()}
            return _ok(payload, "modal_billing", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_billing", started)

    # -- the project ---------------------------------------------------------

    def modal_run_cpu_audit(
        self,
        target_name: str,
        request_id: str,
        run_id: Optional[str] = None,
        run_replay: bool = True,
    ) -> Dict[str, Any]:
        """Run the CPU audit of this repository on one target.

        The target has to have a trusted harness in the repository; the source
        of the target is taken from the repository copy of the server, so that
        a caller cannot audit a source that has no immutable harness. The
        exploit candidate is resolved by the audit service itself out of the
        repository registry.

        The call needs a ``request_id``: it is the key of the replay ledger,
        so that a captured request cannot be executed twice.
        """
        started = time.time()
        try:
            app = self._primary_app()
            self.policy.check_function(app, "audit_contract")

            # Validate target_name and run_id BEFORE writing to _replay_guard
            # so invalid requests cannot poison the 24h replay ledger.
            source = self._target_source(target_name)
            if not source:
                raise PolicyError(
                    "TARGET_SOURCE_UNAVAILABLE",
                    "the target has no repository-owned source with a trusted "
                    "harness, so no verdict could be trusted for it",
                    target_name=target_name,
                    allowed_targets=self._allowed_targets(),
                )

            request: Dict[str, Any] = {
                "target_name": target_name,
                "source_code": source,
                "run_replay": bool(run_replay),
            }
            if run_id is not None:
                self.policy.check_run_id(run_id)
                request["run_id"] = run_id

            self._enforce_rate_limit(
                "audit_contract:minute",
                self.settings.tool_rate_limit_per_min,
                60,
            )
            self._enforce_rate_limit(
                "audit_contract:hourly",
                self.settings.audit_hourly_limit,
                3600,
                code="AUDIT_QUOTA_EXCEEDED",
            )
            self._enforce_rate_limit(
                "audit_contract:daily",
                self.settings.audit_daily_limit,
                86_400,
                code="AUDIT_QUOTA_EXCEEDED",
            )

            self._replay_guard("modal_run_cpu_audit", request_id, {
                "target_name": target_name,
                "run_id": run_id,
                "run_replay": run_replay,
            })

            result = self._call_with_timeout(
                self.access.call_function, app, "audit_contract", request
            )
            payload = {
                "status": "OK",
                "target_name": target_name,
                "request_id": request_id,
                "result": result,
            }
            return _ok(payload, "modal_run_cpu_audit", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_run_cpu_audit", started)

    def modal_read_evidence(self, run_id: str) -> Dict[str, Any]:
        """Read the stored result of one audit run.

        The artifact is read from the committed state of the results volume
        through the API of the volume, and the digest of the stored bytes is
        reported next to the parsed result. The read-back of the audit
        service itself is reported as well, so that a disagreement between
        the two is visible instead of hidden.
        """
        started = time.time()
        try:
            app = self._primary_app()
            self.policy.check_function(app, "read_saved_result")
            self.policy.check_run_id(run_id)
            self._enforce_rate_limit(
                "read_evidence:minute",
                self.settings.tool_rate_limit_per_min,
                60,
            )

            path = f"runs/{run_id}/result.json"
            payload = self.access.read_volume_file(self.settings.results_volume, path)
            if payload is None:
                raise AccessError(
                    "ARTIFACT_NOT_FOUND",
                    "the results volume holds no artifact for this run",
                    run_id=run_id,
                    path=path,
                )

            import hashlib

            digest = hashlib.sha256(payload).hexdigest()
            parsed = None
            parse_error = None
            try:
                parsed = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                parse_error = f"{type(exc).__name__}: {exc}"

            service_readback = None
            try:
                service_readback = self._call_with_timeout(
                    self.access.call_function, app, "read_saved_result", run_id
                )
            except (PolicyError, AccessError) as exc:
                service_readback = {"status": "REFUSED", "error": exc.to_dict()["error"]}

            payload_result = {
                "status": "OK",
                "run_id": run_id,
                "artifact": {
                    "path": path,
                    "byte_length": len(payload),
                    "sha256": digest,
                    "parsed": parsed is not None,
                    "parse_error": parse_error,
                    "result": parsed,
                },
                "service_readback": service_readback,
            }
            return _ok(payload_result, "modal_read_evidence", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_read_evidence", started)

    def modal_list_evidence(self, limit: int = 100) -> Dict[str, Any]:
        """The stored runs of the audit service."""
        started = time.time()
        try:
            bounded = max(1, min(int(limit), 500))
            entries = self.access.list_volume(self.settings.results_volume, "runs")
            payload = {
                "status": "OK",
                "volume": self.settings.results_volume,
                "count": len(entries),
                "runs": [
                    {
                        "run_id": entry["path"].rstrip("/").split("/")[-1],
                        "path": entry["path"],
                        "size": entry["size"],
                    }
                    for entry in entries[:bounded]
                ],
            }
            return _ok(payload, "modal_list_evidence", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_list_evidence", started)

    def modal_environment_probe(self) -> Dict[str, Any]:
        """Probe the environment of the CPU audit service.

        The probe is the evidence that the model cache is mounted read-only,
        that the results volume is writable and that the container of the
        service has no GPU at all.
        """
        started = time.time()
        try:
            app = self._primary_app()
            self.policy.check_function(app, "probe_environment")
            self._enforce_rate_limit(
                "environment_probe:minute",
                self.settings.tool_rate_limit_per_min,
                60,
            )
            result = self._call_with_timeout(
                self.access.call_function, app, "probe_environment", None
            )
            payload = {"status": "OK", "probe": result}
            return _ok(payload, "modal_environment_probe", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_environment_probe", started)

    def modal_run_tests(self, suite: str, request_id: str) -> Dict[str, Any]:
        """Run one of the allowed smoke suites against the CPU audit service.

        The suites are named and closed: ``probe`` asks the service for the
        state of its environment, ``evidence_readback`` reads a stored result
        back and ``candidate_registry`` reports the repository-owned candidate
        registry. There is no way to run an arbitrary test.
        """
        started = time.time()
        try:
            app = self._primary_app()
            if suite not in ALLOWED_TEST_SUITES:
                raise PolicyError(
                    "SUITE_NOT_ALLOWED",
                    "the suite is not one of the allowed smoke suites",
                    suite=suite,
                    allowed=list(ALLOWED_TEST_SUITES),
                )
            self._enforce_rate_limit(
                "run_tests:minute",
                self.settings.tool_rate_limit_per_min,
                60,
            )
            self._replay_guard("modal_run_tests", request_id, {"suite": suite})

            checks: List[Dict[str, Any]] = []
            if suite == "probe":
                self.policy.check_function(app, "probe_environment")
                probe = self._call_with_timeout(
                    self.access.call_function, app, "probe_environment", None
                )
                runtime = (probe or {}).get("runtime", {}) if isinstance(probe, dict) else {}
                checks.append(
                    {
                        "check": "gpu_absent",
                        "passed": not runtime.get("gpu_device_exposed", True),
                        "detail": {
                            "gpu_device_exposed": runtime.get("gpu_device_exposed"),
                            "nvidia_device_nodes": runtime.get("nvidia_device_nodes"),
                        },
                    }
                )
                declared = (probe or {}).get("declared_resources", {}) if isinstance(probe, dict) else {}
                checks.append(
                    {
                        "check": "declared_gpu_is_none",
                        "passed": declared.get("gpu", "missing") is None,
                        "detail": {"declared_gpu": declared.get("gpu")},
                    }
                )
            elif suite == "evidence_readback":
                self.policy.check_function(app, "read_saved_result")
                runs = self.access.list_volume(self.settings.results_volume, "runs")
                if not runs:
                    checks.append(
                        {
                            "check": "evidence_present",
                            "passed": False,
                            "detail": {"reason": "the results volume holds no run"},
                        }
                    )
                else:
                    run_id = runs[0]["path"].rstrip("/").split("/")[-1]
                    self.policy.check_run_id(run_id)
                    payload = self.access.read_volume_file(
                        self.settings.results_volume, f"runs/{run_id}/result.json"
                    )
                    checks.append(
                        {
                            "check": "evidence_present",
                            "passed": payload is not None,
                            "detail": {
                                "run_id": run_id,
                                "byte_length": len(payload) if payload else 0,
                            },
                        }
                    )
            else:  # candidate_registry
                registry_path = os.path.join(self.settings.pocs_dir, "registry.json")
                entries: List[Dict[str, Any]] = []
                if os.path.isfile(registry_path):
                    with open(registry_path, "r", encoding="utf-8") as handle:
                        registry = json.load(handle)
                    for entry in registry.get("entries", []):
                        entries.append(
                            {
                                "target_name": entry.get("target_name"),
                                "expected_outcome": entry.get("expected_outcome"),
                                "expected_vulnerability_class": entry.get("expected_vulnerability_class"),
                            }
                        )
                checks.append(
                    {
                        "check": "candidate_registry_readable",
                        "passed": bool(entries),
                        "detail": {"entries": entries},
                    }
                )

            passed = all(check["passed"] for check in checks)
            payload = {
                "status": "OK",
                "suite": suite,
                "request_id": request_id,
                "passed": passed,
                "checks": checks,
            }
            return _ok(payload, "modal_run_tests", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_run_tests", started)

    # -- the management ------------------------------------------------------

    def modal_deploy_dev(
        self,
        environment: str,
        confirmation: str,
        request_id: str,
    ) -> Dict[str, Any]:
        """Deploy an application into a development environment.

        The operation is switched off by default. It is refused twice: once
        because the write switch of the server is off, and once because the
        first stage of this server ships the interface only - the deployment
        of an application needs the source of that application inside the
        image of the server.
        """
        started = time.time()
        try:
            self.policy.check_environment(environment)
            self.policy.check_write("modal_deploy_dev", confirmation)
            self._replay_guard("modal_deploy_dev", request_id, {"environment": environment})
            raise PolicyError(
                "DEPLOY_NOT_IMPLEMENTED",
                "the first stage of this server ships the interface only; the "
                "deployment of an application needs the source of that "
                "application inside the image of the server",
                environment=environment,
            )
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_deploy_dev", started)

    def modal_stop_app(
        self,
        app: str,
        confirmation: str,
        request_id: str,
    ) -> Dict[str, Any]:
        """Stop one explicitly named application.

        The operation needs the write switch of the server and the
        confirmation value of the owner. Only the applications of the
        allowlist may be stopped.
        """
        started = time.time()
        try:
            self.policy.check_app(app)
            self.policy.check_write("modal_stop_app", confirmation)
            self._replay_guard("modal_stop_app", request_id, {"app": app})
            status = self.access.app_status(app)
            result = self.access.stop_app(status["app_id"])
            payload = {"status": "OK", "app": app, "result": result}
            return _ok(payload, "modal_stop_app", started, max_bytes=self.settings.max_result_bytes)
        except (PolicyError, AccessError) as error:
            return _refusal(error, "modal_stop_app", started)
