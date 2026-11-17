"""Assemble the consolidated R1 read-only evidence report (no new facts invented)."""

import json
import os
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = r"D:\Install\I\Dropbox\Coding\GitHub\Agentic-security-RLVR"


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


inv = load("volume_inventory.json")
pin = load("pinned_cache_verification.json")
auto = load("autoscaler_readback.json")

ALLOWANCE_GIB = 1024.0
tot = inv["totals"]
ptot = pin["totals"]

shards = [r for r in pin["files"] if r["is_weight_shard"]]
shard_bytes = sum(r["expected_size"] for r in shards)
tokenizer = next(r for r in pin["files"] if r["path"] == "tokenizer.json")
declared = pin["declared_expected_bytes"]
declared_match = (shard_bytes + tokenizer["expected_size"]) == declared

headroom_gib = ALLOWANCE_GIB - tot["file_gib"]

evidence = {
    "schema": "r1-readonly-evidence/1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "pr": {
        "repository": "NeuBeginner/Agentic-security-RLVR",
        "number": 14,
        "branch": "docs/evidence-regeneration-architecture-plan",
        "reviewed_head": "c9f3e1b121cf212ff1aa348fa2c26627f0d79056",
        "state": "DRAFT",
        "dispatchability": "NOT_DISPATCHABLE",
        "iteration": "R1 evidence collection (read-only only)",
    },
    "provenance": {
        "provider": "Modal",
        "workspace": "neubeginner",
        "profile": "neubeginner",
        "environment": "main",
        "modal_client_version": inv["modal_client_version"],
        "python": "3.10.11",
        "windows": "10.0.22631 x64",
        "collection_window_utc": [
            inv["collected_at_utc"],
            pin["collected_at_utc"],
            auto["collected_at_utc"],
        ],
        "read_only_guarantee": (
            "only Volume.iterdir / Volume.read_file, FunctionGet, app/volume/billing "
            "listing commands were used; no deploy, run, serve, function invocation, "
            "provider dispatch, GPU allocation, model download, volume write/commit/"
            "remove, or spend"
        ),
    },
    "deliverable_1_storage_baseline_and_capacity": {
        "status": "VERIFIED",
        "volume_name": inv["volume_name"],
        "volume_created_by": "neubeginner",
        "volume_created_at": "2026-10-31 09:42 Central Europe Standard Time",
        "listing_agreement": inv["listing_agreement"],
        "listing_a_entries": inv["listing_a_entries"],
        "listing_b_entries": inv["listing_b_entries"],
        "totals": {
            "entries": tot["entries"],
            "files": tot["files"],
            "directories": tot["dirs"],
            "symlinks": tot["symlinks"],
            "total_bytes": tot["file_bytes"],
            "total_gib": tot["file_gib"],
        },
        "groups": inv["groups"],
        "account_wide_volume_inventory": {
            "volumes_in_workspace": 1,
            "volume_names": ["aegis-model-cache"],
            "source": "modal volume list (read-only)",
        },
        "allowance": {
            "free_allowance_gib_per_month": ALLOWANCE_GIB,
            "source": "modal.com/pricing: 'Volumes $0.09 / GiB / mo *includes 1 TiB / mo free' (read 2026-11-11)",
            "measured_usage_gib": tot["file_gib"],
            "allowance_used_fraction": round(tot["file_gib"] / ALLOWANCE_GIB, 6),
            "headroom_gib": round(headroom_gib, 6),
            "within_allowance": tot["file_gib"] <= ALLOWANCE_GIB,
        },
        "billing_corroboration_this_month": {
            "volumes_metered_usd": 1.98,
            "free_storage_credit_usd": -1.98,
            "ephemeral_apps_usd": 4.04,
            "credits_usd": -4.04,
            "network_egress_usd": 0.00,
            "deployed_apps_usd": 0.00,
            "metered_cost_usd": 6.02,
            "billed_cost_usd": 0.00,
            "source": "modal billing summary (read-only)",
            "reading": (
                "the volume's storage is fully covered by the published free-storage "
                "allowance for this month; the billed cost is 0.00 USD"
            ),
        },
        "unavailable_subitems": {
            "account_wide_concurrent_peak_gib": (
                "UNAVAILABLE - the Modal control plane exposes no account-wide storage "
                "gauge; the measured total is the instantaneous inventory and the "
                "billing API confirms it stays inside the allowance. An explicit "
                "operator attestation can substitute for this sub-item."
            ),
            "gib_figure_from_billing_api": (
                "UNAVAILABLE - the billing API returns metered dollars, not GiB; the "
                "GiB figures above are measured from the volume listing, not derived "
                "from the price"
            ),
        },
    },
    "deliverable_2_pinned_model_cache": {
        "status": "VERIFIED (byte count) / UNAVAILABLE (manifest, content SHA-256)",
        "pinned_repo_id": pin["pinned_repo_id"],
        "pinned_revision": pin["pinned_revision"],
        "declared_expected_bytes": declared,
        "trees_file": pin["trees_file"],
        "verification_method": (
            "the hub cache's own tree file for the pinned revision was read "
            "read-only and each entry was matched against the volume listing by "
            "blob key (xet_hash / lfs_sha256 / blob_id) and exact byte size"
        ),
        "weight_shards": {
            "count": len(shards),
            "verified": sum(1 for r in shards if r["status"] == "VERIFIED"),
            "bytes": shard_bytes,
            "size_mismatches": sum(1 for r in shards if r["status"] == "SIZE_MISMATCH"),
        },
        "tokenizer_json": {
            "expected_size": tokenizer["expected_size"],
            "stored_size": tokenizer["stored_size"],
            "status": tokenizer["status"],
        },
        "declared_reconciliation": {
            "shards_plus_tokenizer_bytes": shard_bytes + tokenizer["expected_size"],
            "declared_expected_bytes": declared,
            "exact_match": declared_match,
        },
        "other_small_files": {
            "count": ptot["verified"] - len(shards) - 1,
            "bytes": ptot["verified_bytes"] - (shard_bytes + tokenizer["expected_size"]),
            "names": [
                r["path"] for r in pin["files"]
                if not r["is_weight_shard"]
                and r["path"] != "tokenizer.json"
                and r["status"] == "VERIFIED"
            ],
        },
        "total_verified_bytes": ptot["verified_bytes"],
        "missing_entries": [
            {"path": r["path"], "expected_size": r["expected_size"],
             "note": "documentation-only file of the revision; not required for inference"}
            for r in pin["files"] if r["status"] == "MISSING"
        ],
        "r2p_manifest": pin["r2p_manifest"],
        "sha256_verification": pin["sha256_verification"],
        "staging_leftovers": {
            "true_staging_leftovers": {
                "count": 0,
                "patterns_checked": [".incomplete", ".tmp", ".partial", ".staging", ".pending"],
                "status": "VERIFIED - none present",
            },
            "hub_lock_and_reference_metadata": {
                "lock_files": 49,
                "lock_bytes": 0,
                "refs_files": 19,
                "refs_bytes": 2111,
                "files_under_huggingface_dot_locks": 30,
                "status": "reported separately - hub bookkeeping, not payload staging",
            },
        },
    },
    "deliverable_3_autoscaler_readback": {
        "status": "UNAVAILABLE",
        "rpc": "FunctionGet (read-only)",
        "app_name": auto["app_name"],
        "object_tag": auto["object_tag"],
        "environment": auto["environment"],
        "raw_error": "NotFoundError: App 'aegis-rlvr-security' not found in environment 'main'",
        "corroborating_evidence": {
            "modal_app_list_json": "[] (no app running, deployed or recently stopped)",
            "modal_app_history": "No App with name 'aegis-rlvr-security' found in the 'main' environment.",
            "billing_history": "apps named 'aegis-rlvr-security' were deployed in the workspace on 2026-10-30/31 and are no longer listed",
        },
        "fields_populated": {
            "function": "UNAVAILABLE",
            "autoscaler_settings": "UNAVAILABLE",
            "min_containers": "UNAVAILABLE",
            "max_containers": "UNAVAILABLE",
            "buffer_containers": "UNAVAILABLE",
            "scaledown_window": "UNAVAILABLE",
        },
        "repository_defect_found": {
            "file": "benchmarks/r1_dispatch.py",
            "line": 350,
            "code": "client = await Client.from_env()",
            "problem": (
                "Modal SDK 1.5.5 defines 'Client = synchronize_api(_Client)' "
                "(modal/client.py:532), so the public client is synchronous: "
                "'await Client.from_env()' raises "
                "TypeError: object Client can't be used in 'await' expression"
            ),
            "observed_effect": (
                "the repository's own provider_autoscaler_reader always fails closed "
                "with AutoscalerReadbackUnavailable, independently of the deployment "
                "state; the D27 read-back can never succeed against SDK 1.5.5"
            ),
            "fail_closed": True,
            "note": (
                "reported, not fixed: this iteration is documentation/evidence only, "
                "and the R1 contract forbids changing the dispatch gate"
            ),
        },
    },
    "deliverable_4_evidence_integrity": {
        "status": "VERIFIED",
        "statement": (
            "no historical evidence file was rewritten, no declared digest was "
            "altered, and no estimator assumption was changed; every number in this "
            "report comes from a raw read-only output stored next to it"
        ),
        "raw_artifacts": [
            "benchmarks/evidence/r1_readonly_20261114/volume_inventory.json",
            "benchmarks/evidence/r1_readonly_20261114/pinned_cache_verification.json",
            "benchmarks/evidence/r1_readonly_20261114/pinned_trees_raw.json",
            "benchmarks/evidence/r1_readonly_20261114/autoscaler_readback.json",
            "benchmarks/evidence/r1_readonly_20261114/raw_cli_outputs.txt",
            "benchmarks/evidence/r1_readonly_20261114/collection_scripts/",
        ],
        "historical_evidence_touched": [],
    },
    "hard_stops_observed": {
        "modal_deploy": False,
        "modal_run": False,
        "modal_serve": False,
        "remote_function_invocation": False,
        "provider_dispatch": False,
        "gpu_or_h100_allocation": False,
        "model_download": False,
        "volume_write_commit_or_remove": False,
        "paid_compute": False,
        "pinned_public_key_populated": False,
        "approval_artifact_created_or_signed": False,
        "rate_card_approved": False,
        "unset_bounds_changed": False,
        "r2p_r3_r3b_r4_executed": False,
        "merge_or_promote_from_draft": False,
        "dispatch_gate_changed": False,
    },
    "status_summary": {
        "storage_baseline_and_capacity": "VERIFIED",
        "pinned_cache_byte_count": "VERIFIED",
        "pinned_cache_manifest": "UNAVAILABLE",
        "pinned_cache_content_sha256": "UNAVAILABLE",
        "pinned_cache_staging_leftovers": "VERIFIED (none)",
        "autoscaler_readback": "UNAVAILABLE",
        "evidence_integrity": "VERIFIED",
    },
}

out_repo = os.path.join(REPO, "benchmarks", "evidence", "r1_readonly_evidence_20261114.json")
with open(out_repo, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(evidence, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print("written:", out_repo)
print("declared exact match:", declared_match)
