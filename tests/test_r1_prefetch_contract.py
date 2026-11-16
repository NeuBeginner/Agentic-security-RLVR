"""The R1 contract of the model-cache prefetch (R2p) and of the D28 payload cap.

The proofs this file carries:

* the prefetch is **idempotent** - a materialised cache is verified and its
  manifest written, and nothing is downloaded a second time;
* the **cold** path refuses while the retry allowance of the download is not
  approved: a refusal is never a download (D29);
* the manifest the prefetch writes is the manifest the **GPU class** verifies -
  the two agree, and an incomplete cache fails **closed** (D29);
* the D28 payload cap is **approved** and enforced (1 MiB).

Everything here is local: no test performs a provider call, a deployment, a
volume operation or a model download.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

import pytest

from core import r1_bounds as r1
from core import r1_approval


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _repo_dirname() -> str:
    return "models--" + r1.PINNED_MODEL.repo_id.replace("/", "--")


def _materialise(cache_dir: Path, sizes: dict) -> Path:
    """A materialised snapshot of the pinned revision - plain files."""
    snapshot = (
        cache_dir
        / _repo_dirname()
        / "snapshots"
        / r1.PINNED_MODEL.revision
    )
    snapshot.mkdir(parents=True, exist_ok=True)
    for name, size in sizes.items():
        (snapshot / name).write_bytes(b"x" * size)
    return snapshot


def _sizes(*entries) -> dict:
    return {name: size for name, size in entries}


# --------------------------------------------------------------------------------------
# the prefetch is idempotent
# --------------------------------------------------------------------------------------


def test_a_materialised_cache_without_a_manifest_only_needs_the_manifest(tmp_path):
    """The cache is there: the step writes the manifest and downloads nothing."""
    import modal_app

    cache_dir = tmp_path / "huggingface"
    snapshot = _materialise(cache_dir, _sizes(("config.json", 10), ("model.safetensors", 64)))
    manifest_path = tmp_path / "model_cache_manifest.json"

    plan = modal_app._prefetch_plan(str(cache_dir), str(manifest_path), str(snapshot))
    assert plan["action"] == "WRITE_MANIFEST"
    assert plan["downloaded_bytes"] == 0
    assert len(plan["files"]) == 2


def test_a_materialised_cache_with_a_verifying_manifest_is_not_rewritten(tmp_path):
    """The second attempt of R2p verifies the cache and downloads nothing."""
    import modal_app

    cache_dir = tmp_path / "huggingface"
    snapshot = _materialise(cache_dir, _sizes(("config.json", 10), ("model.safetensors", 64)))
    manifest_path = tmp_path / "model_cache_manifest.json"

    files = modal_app._collect_cache_files(str(cache_dir), str(snapshot))
    manifest = modal_app._build_cache_manifest(files, "2026-11-16T00:00:00Z")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    plan = modal_app._prefetch_plan(str(cache_dir), str(manifest_path), str(snapshot))
    assert plan["action"] == "ALREADY_MATERIALISED"
    assert plan["downloaded_bytes"] == 0
    assert plan["manifest"]["revision"] == r1.PINNED_MODEL.revision


def test_an_empty_cache_takes_the_cold_path(tmp_path):
    """Nothing is materialised: the step has to download - under a bound."""
    import modal_app

    cache_dir = tmp_path / "huggingface"
    cache_dir.mkdir()
    snapshot = cache_dir / _repo_dirname() / "snapshots" / r1.PINNED_MODEL.revision
    manifest_path = tmp_path / "model_cache_manifest.json"

    plan = modal_app._prefetch_plan(str(cache_dir), str(manifest_path), str(snapshot))
    assert plan["action"] == "DOWNLOAD"


def test_the_cold_path_refuses_while_the_retry_allowance_is_unapproved():
    """A refusal is never a download: the bound of the download is not approved."""
    assert r1.is_unset(r1.DOWNLOAD_RETRY_ALLOWANCE)
    with pytest.raises(r1.BoundsNotApproved):
        r1.prefetch_ingress_cap_bytes()


# --------------------------------------------------------------------------------------
# the manifest is the one the GPU class verifies
# --------------------------------------------------------------------------------------


def test_the_written_manifest_verifies_against_the_cache(tmp_path):
    """The manifest the prefetch writes is accepted by the GPU class' check."""
    import modal_app

    cache_dir = tmp_path / "huggingface"
    snapshot = _materialise(cache_dir, _sizes(("config.json", 10), ("model.safetensors", 64)))
    files = modal_app._collect_cache_files(str(cache_dir), str(snapshot))
    manifest = modal_app._build_cache_manifest(files, "2026-11-16T00:00:00Z")

    check = r1.verify_model_cache_manifest(str(cache_dir), manifest)
    assert check["status"] == "PASSED"
    assert check["checked"] == 2
    assert manifest["repo_id"] == r1.PINNED_MODEL.repo_id
    assert manifest["revision"] == r1.PINNED_MODEL.revision
    assert manifest["bytes_total"] == 74


def test_an_incomplete_cache_fails_closed_against_the_manifest(tmp_path):
    """A file that is missing makes the GPU class refuse the container."""
    import modal_app

    cache_dir = tmp_path / "huggingface"
    snapshot = _materialise(cache_dir, _sizes(("config.json", 10), ("model.safetensors", 64)))
    files = modal_app._collect_cache_files(str(cache_dir), str(snapshot))
    manifest = modal_app._build_cache_manifest(files, "2026-11-16T00:00:00Z")

    (snapshot / "model.safetensors").unlink()
    check = r1.verify_model_cache_manifest(str(cache_dir), manifest)
    assert check["status"] == "FAILED"
    assert check["missing"]


def test_a_changed_byte_size_fails_closed_against_the_manifest(tmp_path):
    """A truncated shard fails the check: the size is part of the manifest."""
    import modal_app

    cache_dir = tmp_path / "huggingface"
    snapshot = _materialise(cache_dir, _sizes(("config.json", 10), ("model.safetensors", 64)))
    files = modal_app._collect_cache_files(str(cache_dir), str(snapshot))
    manifest = modal_app._build_cache_manifest(files, "2026-11-16T00:00:00Z")

    (snapshot / "model.safetensors").write_bytes(b"x" * 63)
    check = r1.verify_model_cache_manifest(str(cache_dir), manifest)
    assert check["status"] == "FAILED"
    assert check["mismatched"]


def test_the_manifest_carries_no_recomputed_digest():
    """The GPU container verifies the manifest on every start: no re-hashing.

    Re-hashing 59.9 GiB per container start is not affordable (R4 starts up to
    32 containers), so the manifest carries the path, the size and the hub's own
    blob id - never a recomputed SHA-256.
    """
    import modal_app

    files = [{"path": "a/b", "size": 1, "blob_id": "abc"}]
    manifest = modal_app._build_cache_manifest(files, "2026-11-16T00:00:00Z")
    assert all("sha256" not in entry for entry in manifest["files"])


# --------------------------------------------------------------------------------------
# the call site of the step
# --------------------------------------------------------------------------------------


def test_the_prefetch_is_an_authorised_call_site_of_the_sandbox_class():
    import modal_app
    from core import r1_bounds as bounds

    assert bounds.FUNCTION_CLASS["prefetch_model_cache_remote"] == bounds.SANDBOX_CPU
    # The guard is installed on the provider object itself at import time.
    assert isinstance(modal_app.prefetch_model_cache_remote, bounds.GuardedRemote)


def test_the_prefetch_image_carries_the_sources_of_the_repository():
    """The prefetch container must be able to import the deployed module.

    The deployed ``modal_app`` imports ``core.config`` and ``core.r1_bounds``
    at import time, so an image without the repository's sources cannot even
    start the container: the import fails with ``ModuleNotFoundError: No
    module named 'core'`` and the step crash-loops instead of running.
    """
    import ast

    source = (
        (Path(__file__).resolve().parent.parent / "modal_app.py").read_text(encoding="utf-8")
    )
    tree = ast.parse(source)
    definition = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "prefetch_image"
            for target in node.targets
        ):
            definition = node.value
            break
    assert definition is not None, "modal_app.py does not define prefetch_image"

    sources = set()
    for node in ast.walk(definition):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_local_python_source"
        ):
            for argument in node.args:
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    sources.add(argument.value)
    assert {"core", "sandbox"} <= sources, (
        "the image of the prefetch step does not carry the repository's sources: "
        f"it carries {sorted(sources)}"
    )


def test_the_prefetch_declares_the_egress_policy_of_its_class():
    import modal_app

    policy = r1.EGRESS_POLICIES["prefetch_model_cache_remote"]
    assert policy.container_class == r1.SANDBOX_CPU
    # The model is **downloaded**: the outbound payload of the step is zero.
    assert policy.payload_cap_bytes == 0
    # The download is ingress and is declared separately (D29).
    ingress = r1.INGRESS_POLICIES["prefetch_model_cache_remote"]
    assert r1.is_unset(ingress.ingress_cap_bytes)
    assert r1.prefetch_ingress_cap_bytes.__doc__ is not None


def test_the_prefetch_timeout_and_the_hub_client_are_bound_declarations():
    """Both are approval inputs of the envelope of every step."""
    assert r1.PREFETCH_TIMEOUT_SEC == 3600
    assert r1.HUGGINGFACE_HUB_VERSION

    from benchmarks import r1_dispatch

    policy = r1_dispatch.StepPolicy(
        step_id="R3",
        invocation_budgets={r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        concurrency_caps={r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        wall_clock_budget_sec=1200.0,
        post_execution_deadline_sec=3600.0,
        monetary_ceiling_usd=5.0,
        estimate_usd=0.5,
        approved_by="test",
        approved_at="2026-11-16",
    )
    envelope = r1_dispatch.DispatchGate(policy=policy).dispatch_envelope_payload()
    assert envelope["model_cache"]["prefetch_timeout_sec"] == 3600
    assert envelope["model_cache"]["huggingface_hub_version"] == r1.HUGGINGFACE_HUB_VERSION


# --------------------------------------------------------------------------------------
# the D28 payload cap is approved
# --------------------------------------------------------------------------------------


def test_the_payload_cap_is_approved_and_enforced():
    assert r1.MAX_TRAJECTORY_PAYLOAD_BYTES == 1024 * 1024
    r1.assert_payload_within_cap(1024 * 1024, "record_trajectory_remote")
    with pytest.raises(r1.BoundsNotApproved):
        r1.assert_payload_within_cap(1024 * 1024 + 1, "record_trajectory_remote")


def test_the_envelope_binds_the_approved_payload_cap():
    from benchmarks import r1_dispatch

    policy = r1_dispatch.StepPolicy(
        step_id="R3",
        invocation_budgets={r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        concurrency_caps={r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        wall_clock_budget_sec=1200.0,
        post_execution_deadline_sec=3600.0,
        monetary_ceiling_usd=5.0,
        estimate_usd=0.5,
        approved_by="test",
        approved_at="2026-11-16",
    )
    envelope = r1_dispatch.DispatchGate(policy=policy).dispatch_envelope_payload()
    assert envelope["payload_cap"] == 1024 * 1024


# --------------------------------------------------------------------------------------
# the scenario: every step declares every class
# --------------------------------------------------------------------------------------


def test_every_step_declares_a_budget_and_a_cap_for_every_container_class():
    """The gate refuses an incomplete policy - the scenario has to be complete."""
    scenario = json.loads(
        (Path(__file__).resolve().parent.parent / "benchmarks" / "evidence" / "r1_cost_scenario.json")
        .read_text(encoding="utf-8")
    )
    for step in scenario["steps"]:
        for container_class in set(r1.FUNCTION_CLASS.values()):
            assert container_class in step["invocations"], (step["step_id"], container_class)
            assert container_class in step["concurrency_caps"], (step["step_id"], container_class)


def test_the_unused_classes_are_declared_with_a_zero():
    """R2p and R3 declare the classes they do not use with a zero."""
    scenario = json.loads(
        (Path(__file__).resolve().parent.parent / "benchmarks" / "evidence" / "r1_cost_scenario.json")
        .read_text(encoding="utf-8")
    )
    steps = {step["step_id"]: step for step in scenario["steps"]}
    for step_id in ("R2p", "R3"):
        step = steps[step_id]
        assert step["invocations"]["sandbox_cpu"] == 1
        assert step["invocations"]["gpu"] == 0
        assert step["invocations"]["persistence"] == 0
        assert step["concurrency_caps"]["gpu"] == 0
        assert step["concurrency_caps"]["persistence"] == 0


def test_a_class_without_invocations_contributes_nothing_to_the_estimate():
    """A class with zero invocations starts no container: no cost, no bounds."""
    from benchmarks import r1_estimator

    scenario = json.loads(
        (Path(__file__).resolve().parent.parent / "benchmarks" / "evidence" / "r1_cost_scenario.json")
        .read_text(encoding="utf-8")
    )
    rate_card = r1_estimator.RateCard.from_file(
        str(Path(__file__).resolve().parent.parent / "benchmarks" / "evidence" / "r1_rate_card.json")
    )
    result = r1_estimator.run_scenario(scenario, rate_card)
    steps = {step["step_id"]: step for step in result["steps"]}
    for step_id in ("R2p", "R3"):
        step = steps[step_id]
        assert step["available"] is True, step.get("unavailable_reasons")
        quantities = step["quantities"]
        assert "gpu" not in quantities
        assert "persistence" not in quantities
        assert quantities["sandbox_cpu"]["invocations"] == 1
