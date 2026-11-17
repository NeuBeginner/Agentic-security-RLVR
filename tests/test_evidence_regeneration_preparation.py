"""The preparation of the evidence regeneration: the inventory, the field map
and the refusal of a fabricated Modal URI in a new run.

The suite states four things:

* the inventory of the published artifacts tree is **exactly** the 165
  documented occurrences - 66 in the 16 target artifacts, 33 in the
  reproducibility manifest, 33 in the summary of the run and 33 in the
  root-level ``latest_summary.json``;
* every one of them sits in the legacy ``durable_log_ref`` field of a stage of
  the Modal invocation provenance;
* the published run directory is **untouched**: its files still hash to the
  digests the published manifest records; and
* a new run that carries a fabricated URI is **refused** - by the provenance
  validator in its legacy fields and by the top-level refusal in every other
  field.

Everything here is local: no provider call, no deployment, no volume
operation, no model download and no paid computation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks import prepare_evidence_regeneration as prep
from benchmarks.evidence_integrity import (
    has_synthetic_modal_uri,
    validate_modal_invocation_provenance,
)
from benchmarks.protocol import reject_synthetic_modal_uris

REPO_ROOT = Path(__file__).resolve().parent.parent
PUBLISHED_RUN = REPO_ROOT / "benchmarks" / "artifacts" / "run_1794209615_70f5d22"


# --------------------------------------------------------------------------------------
# the inventory
# --------------------------------------------------------------------------------------


def test_the_inventory_is_exactly_the_165_documented_occurrences():
    """165 occurrences in 19 files - the count of the plan, reproduced here."""
    inventory = prep.build_inventory()
    assert inventory["total_occurrences"] == 165
    assert inventory["files_with_occurrences"] == 19


def test_the_inventory_has_the_documented_distribution():
    """66 in the target artifacts, 33 in the manifest, 33 in the summary, 33 in latest_summary."""
    inventory = prep.build_inventory()
    counts = {row["file"]: row["occurrences"] for row in inventory["files"]}

    run_dir = prep.PUBLISHED_RUN_DIR
    target_artifacts = sum(
        count for path, count in counts.items() if f"{run_dir}/baseline_5/" in path
    )
    assert target_artifacts == 66
    assert counts[f"{run_dir}/reproducibility_manifest.json"] == 33
    assert counts[f"{run_dir}/summary.json"] == 33
    assert counts[prep.PUBLISHED_LATEST_SUMMARY] == 33


def test_every_occurrence_is_the_legacy_durable_log_ref_of_a_stage():
    """The fabricated URIs are the legacy log-URI fields of the stages."""
    inventory = prep.build_inventory()
    for occurrence in inventory["occurrences"]:
        assert occurrence["json_path"].endswith(".durable_log_ref")
        assert "modal_invocation_provenance.stages." in occurrence["json_path"]
        assert occurrence["field"] == "durable_log_ref"
        assert occurrence["stage"]


def test_the_field_map_names_the_contract_of_a_new_run():
    """Every occurrence of the map says what replaces it and what refuses it."""
    field_map = prep.build_field_map(prep.build_inventory())
    assert field_map["total_occurrences"] == 165
    assert field_map["published_run_dir_is_immutable"] is True
    assert len(field_map["field_map"]) == 165
    for entry in field_map["field_map"]:
        assert entry["replacement"]
        assert "reject_synthetic_modal_uris" in entry["refused_by"]
        assert entry["value_sha256"]


def test_the_inventory_reads_the_git_blobs_and_not_the_working_tree():
    """The inventory is the same on every machine: it reads the committed bytes."""
    source = (REPO_ROOT / "benchmarks" / "prepare_evidence_regeneration.py").read_text(
        encoding="utf-8"
    )
    assert "cat-file" in source
    assert "ls-files" in source


# --------------------------------------------------------------------------------------
# the historical record
# --------------------------------------------------------------------------------------


def test_the_published_run_directory_is_untouched():
    """Nothing of the published run is committed or modified."""
    report = prep.verify_published_run()
    assert report["untouched"] is True
    assert report["committed_changes"] == ""
    assert report["working_tree_changes"] == ""


def test_the_published_files_still_hash_to_the_digests_of_the_manifest():
    """The historical digests still hold - the run directory was not rewritten."""
    manifest = json.loads(
        (PUBLISHED_RUN / "reproducibility_manifest.json").read_text(encoding="utf-8")
    )
    recorded = {
        row["relative_path"]: row["sha256"]
        for row in manifest["adapters"]["baseline_5"]["artifact_files"]
    }
    assert recorded

    inventory = prep.build_inventory()
    checked = 0
    for row in inventory["files"]:
        relative = row["file"].split("benchmarks/artifacts/", 1)[1]
        if relative not in recorded:
            continue
        assert row["sha256"] == recorded[relative], relative
        checked += 1
    assert checked >= 16


# --------------------------------------------------------------------------------------
# the refusal of a fabricated URI in a new run
# --------------------------------------------------------------------------------------


def _modern_provenance() -> dict:
    """A provenance block of the current contract - no fabricated URI."""
    return {
        "modal_invocation_provenance": {
            "stages": {
                "evm_sandbox": {
                    "app_id": "ap-EXAMPLE1234",
                    "function_call_id": "fc-EXAMPLE1234",
                    "container_id": "ci-EXAMPLE1234",
                }
            }
        }
    }


def test_the_provenance_validator_accepts_a_clean_new_run():
    """The contract of a new run is accepted - the refusal is specific."""
    ok, error = validate_modal_invocation_provenance(_modern_provenance())
    assert ok is True
    assert error is None


def test_the_provenance_validator_refuses_a_fabricated_uri_in_a_legacy_field():
    """The legacy log-URI fields of a stage are refused."""
    artifact = _modern_provenance()
    artifact["modal_invocation_provenance"]["stages"]["evm_sandbox"]["durable_log_ref"] = (
        "modal-app://ap-EXAMPLE1234/inference/X"
    )
    ok, error = validate_modal_invocation_provenance(artifact)
    assert ok is False
    assert "synthetic log URI" in (error or "")


def test_the_top_level_refusal_covers_every_field():
    """A fabricated URI in **any** field is refused - not only in the legacy ones."""
    artifact = _modern_provenance()
    artifact["a_new_field_of_a_new_run"] = "modal-app://ap-EXAMPLE1234/inference/X"

    assert has_synthetic_modal_uri(artifact) is True
    ok, error = reject_synthetic_modal_uris(artifact)
    assert ok is False
    assert "modal-app://" in (error or "")

    # The clean artifact passes both.
    clean = _modern_provenance()
    assert has_synthetic_modal_uri(clean) is False
    assert reject_synthetic_modal_uris(clean) == (True, None)


@pytest.mark.parametrize(
    "validator",
    [
        "benchmarks/validate_iteration14_evidence.py",
        "benchmarks/validate_iteration15_evidence.py",
        "benchmarks/validate_iteration16_evidence.py",
    ],
)
def test_the_iteration_validators_of_the_run_call_the_refusal(validator):
    """The validators of the 16-target run refuse a fabricated URI themselves."""
    source = (REPO_ROOT / validator).read_text(encoding="utf-8")
    assert "reject_synthetic_modal_uris" in source
    assert "validate_modal_invocation_provenance" in source


# --------------------------------------------------------------------------------------
# the preparation stops before the run
# --------------------------------------------------------------------------------------


def test_the_preparation_performs_no_provider_call():
    """The preparation script imports no provider SDK and runs nothing."""
    source = (REPO_ROOT / "benchmarks" / "prepare_evidence_regeneration.py").read_text(
        encoding="utf-8"
    )
    for forbidden in ("import modal", "modal.App", ".remote(", "subprocess.run(\"modal"):
        assert forbidden not in source


def test_the_plan_is_prepared_and_not_executed():
    """The plan of the new run is a proposal: it is never executed by the script."""
    plan = prep.plan_run()
    assert plan["status"] == "PREPARED - NOT AUTHORISED, NOT EXECUTED"
    assert plan["run_id"].startswith("run_<epoch>_")
    assert plan["commit_sha"]
    assert plan["steps"]
    assert any("not modified" in line for line in plan["never"])
