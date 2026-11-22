"""
core/patch_generator.py
=======================

Blue-team LLM patch synthesis, verifier-guided refinement, and Red->Blue
Dual-Loop rollout collection (`Exploit -> Verified Patch`).
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from core.patch_verifier import (
    BluePatchCategory,
    DualLoopRecord,
    PatchCandidate,
    PatchVerificationResult,
    PatchRunnerFn,
    RedVerifierFn,
    verify_patch,
)
from core.schemas import ResultCategory, TargetProgram
from sandbox.patch_runner import PatchSandboxResult

DEFAULT_BLUE_TEMPERATURES: Tuple[float, ...] = (0.2, 0.4, 0.7, 0.9)
MAX_SANDBOX_FEEDBACK_CHARS = 1200

_FENCED_SOL_RE = re.compile(r"```(?:solidity|sol)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

PatchGeneratorFn = Callable[[TargetProgram, str, float, int], str]


def build_patch_system_prompt() -> str:
    """Return the system prompt for minimal, idiomatic Solidity security patching."""
    return (
        "You are an expert Solidity security engineer performing automated vulnerability remediation.\n"
        "Output ONLY a single ```solidity ... ``` code block containing the complete patched `contract <TargetName>`.\n"
        "Rules:\n"
        "- Preserve ALL existing external/public function signatures, events, and state getters.\n"
        "- Apply the minimal, idiomatic fix (e.g., access control checks, Checks-Effects-Interactions, "
        "virtual offset / dead shares, initializer guards, or non-zero eta checks).\n"
        "- NEVER use `vm.*`, `forge-std`, `selfdestruct`, or trivial `revert()` stubs that break legitimate users."
    )


def build_patch_prompt(target: TargetProgram, red_exploit_code: str) -> str:
    """Build the initial Blue-team patching prompt from target source and confirmed Red exploit."""
    invariants_text = "\n".join(f"- {inv}" for inv in target.invariants) if target.invariants else "- Preserve protocol invariants"
    return (
        f"Patch `contract {target.name}` so that the confirmed exploit below is blocked while all legitimate "
        f"functionality continues to work.\n\n"
        f"Target Contract (`src/{target.name}.sol`):\n"
        f"```solidity\n{target.source_code}\n```\n\n"
        f"Security Invariants:\n{invariants_text}\n\n"
        f"Confirmed Red Exploit (`test/ExploitModule.sol`):\n"
        f"```solidity\n{red_exploit_code}\n```\n\n"
        f"Return ONLY the complete patched `src/{target.name}.sol` inside one ```solidity ... ``` block."
    )


def format_sandbox_feedback(sb_res: Optional[PatchSandboxResult], verification_result: PatchVerificationResult) -> str:
    """Format concrete Foundry sandbox diagnostics bounded to <= 1200 characters."""
    parts: List[str] = []
    if sb_res is not None:
        if sb_res.compile_error:
            parts.append(f"Compiler error:\n{sb_res.compile_error}")
        elif not sb_res.functional_pass:
            detail = (sb_res.functional_stderr or sb_res.functional_stdout or "").strip()
            parts.append(f"Functional test failure:\n{detail}")
        elif not sb_res.exploit_blocked:
            detail = f"Breach events: {sb_res.breach_events}"
            if sb_res.security_stderr:
                detail += f"\n{sb_res.security_stderr.strip()}"
            parts.append(detail)
    if not parts and verification_result.reason:
        parts.append(verification_result.reason)
    text = "\n".join(parts).strip() or f"Failed with {verification_result.category.value}"
    return text[:MAX_SANDBOX_FEEDBACK_CHARS]


def build_patch_refinement_prompt(
    target: TargetProgram,
    red_exploit_code: str,
    failed_patch: str,
    verification_result: PatchVerificationResult,
    sandbox_feedback: str = "",
) -> str:
    """Build a verifier-guided Blue refinement prompt bounded to <= 1200 chars of feedback."""
    bounded_feedback = (sandbox_feedback or verification_result.reason or "")[:MAX_SANDBOX_FEEDBACK_CHARS]
    guidance_map = {
        BluePatchCategory.PATCH_COMPILATION_ERROR: "Fix the Solidity compiler error while preserving all public/external signatures.",
        BluePatchCategory.FUNCTIONAL_REGRESSION: "Your patch broke legitimate protocol functionality. Keep normal user/owner flows working.",
        BluePatchCategory.EXPLOIT_STILL_SUCCEEDS: "The Red exploit still succeeded. Close the exact vulnerability vector without breaking normal flows.",
        BluePatchCategory.PATCH_FORMAT_ERROR: f"Return a complete, non-trivial `contract {target.name}` in one ```solidity ... ``` block.",
    }
    guidance = guidance_map.get(verification_result.category, "Fix the reported verification failure.")

    return (
        f"Your previous patch for `contract {target.name}` failed Blue verification with `{verification_result.category.value}`.\n"
        f"Action required: {guidance}\n\n"
        f"--- FOUNDRY VERIFIER FEEDBACK ---\n{bounded_feedback}\n---------------------------------\n\n"
        f"Original Contract (`src/{target.name}.sol`):\n"
        f"```solidity\n{target.source_code}\n```\n\n"
        f"Confirmed Red Exploit:\n"
        f"```solidity\n{red_exploit_code}\n```\n\n"
        f"Your Previous Failed Patch:\n"
        f"```solidity\n{failed_patch}\n```\n\n"
        f"Return ONLY the repaired `src/{target.name}.sol` inside one ```solidity ... ``` block."
    )


def parse_patch_response(raw_response: str, target_name: str, candidate_id: str = "") -> PatchCandidate:
    """Extract patched Solidity code from a ```solidity ... ``` block (with pragma/contract fallback)."""
    text = (raw_response or "").strip()
    extracted = ""
    matches = _FENCED_SOL_RE.findall(text)
    if matches:
        for block in matches:
            if re.search(rf"\bcontract\s+{re.escape(target_name)}\b", block):
                extracted = block.strip()
                break
        if not extracted:
            extracted = matches[0].strip()
    else:
        pragma_idx = text.find("pragma solidity")
        spdx_idx = text.find("// SPDX-License-Identifier")
        start_idx = spdx_idx if spdx_idx != -1 else pragma_idx
        if start_idx != -1:
            extracted = text[start_idx:].strip()
        else:
            extracted = text

    return PatchCandidate(
        target_name=target_name,
        patched_source=extracted,
        candidate_id=candidate_id,
    )


def load_confirmed_red_exploits_from_dirs(
    trajectory_dirs: Sequence[str],
    target_names: Sequence[str],
) -> Dict[str, Dict[str, str]]:
    """
    Scan persisted RLVR trajectory directories and pick the first confirmed
    `EXPLOIT_CONFIRMED` exploit for each requested target.
    """
    wanted = set(target_names)
    found: Dict[str, Dict[str, str]] = {}

    for dir_str in trajectory_dirs:
        p = Path(dir_str)
        if not p.is_dir():
            continue
        for json_file in sorted(p.glob("*.json")):
            try:
                rec = json.loads(json_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            tname = str(rec.get("target_name") or "")
            if tname not in wanted or tname in found:
                continue
            cat = str(rec.get("category") or rec.get("result_category") or "")
            code = str(rec.get("exploit_code") or rec.get("test_code") or "").strip()
            if cat == ResultCategory.EXPLOIT_CONFIRMED.value and code:
                found[tname] = {
                    "target_name": tname,
                    "exploit_code": code,
                    "trajectory_id": str(rec.get("trajectory_id") or json_file.stem),
                    "source_dir": str(p),
                }
            if len(found) == len(wanted):
                return found

    return found


def collect_blue_patch_rollouts(
    *,
    targets: Iterable[TargetProgram],
    red_exploits: Dict[str, Dict[str, str]],
    output_dir: str,
    generator_fn: PatchGeneratorFn,
    red_verifier: Optional[RedVerifierFn] = None,
    patch_runner: Optional[PatchRunnerFn] = None,
    group_size: int = 4,
    temperatures: Optional[Sequence[float]] = None,
    max_refinement_rounds: int = 1,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run Red -> Blue patch synthesis and verification across targets, supporting
    early-stop on `PATCH_VERIFIED`, best-of-rounds selection, and honest
    `improved_in_refinement` tracking.
    """
    if not (1 <= group_size <= 4):
        raise ValueError(f"group_size must be between 1 and 4, got {group_size}")
    if not (0 <= max_refinement_rounds <= 2):
        raise ValueError(f"max_refinement_rounds must be between 0 and 2, got {max_refinement_rounds}")

    temps = list(temperatures) if temperatures else list(DEFAULT_BLUE_TEMPERATURES)
    sched = [float(temps[i % len(temps)]) for i in range(group_size)]
    active_run_id = run_id or f"dual_loop_{uuid.uuid4().hex[:8]}"
    os.makedirs(output_dir, exist_ok=True)

    category_counts: Dict[str, int] = {}
    rewards: List[float] = []
    improved_by_refinement_count = 0
    persisted_paths: List[str] = []
    best_patches_by_target: Dict[str, Dict[str, Any]] = {}
    verified_targets: List[str] = []
    total_candidates = 0

    for target in targets:
        if target.name not in red_exploits:
            raise ValueError(f"No confirmed Red exploit provided for target '{target.name}'")
        red_info = red_exploits[target.name]
        red_code = red_info["exploit_code"]
        red_traj_id = red_info.get("trajectory_id", "")
        init_prompt = build_patch_prompt(target, red_code)

        target_best_res: Optional[PatchVerificationResult] = None
        target_best_code = ""

        for cand_idx, temp in enumerate(sched):
            last_sb: Dict[str, Optional[PatchSandboxResult]] = {"res": None}

            def _recording_runner(tname: str, psrc: str, ecode: str) -> PatchSandboxResult:
                if patch_runner is not None:
                    r = patch_runner(tname, psrc, ecode)
                else:
                    from sandbox.patch_runner import run_patch_in_sandbox

                    r = run_patch_in_sandbox(tname, psrc, ecode)
                last_sb["res"] = r
                return r

            cand_id = f"{active_run_id}_{target.name}_p{cand_idx}"
            raw_0 = generator_fn(target, init_prompt, temp, cand_idx)
            cand_0 = parse_patch_response(raw_0, target.name, candidate_id=cand_id)
            res_0 = verify_patch(
                target_name=target.name,
                original_source=target.source_code,
                candidate=cand_0,
                exploit_code=red_code,
                red_precondition_verified=False,
                red_verifier=red_verifier,
                patch_runner=_recording_runner,
            )

            best_cand = cand_0
            best_res = res_0
            best_sb = last_sb["res"]
            improved_in_refinement = False

            if (
                max_refinement_rounds > 0
                and best_res.category not in (BluePatchCategory.PATCH_VERIFIED, BluePatchCategory.PATCH_INFRA_ERROR)
            ):
                for r_idx in range(1, max_refinement_rounds + 1):
                    fb = format_sandbox_feedback(best_sb, best_res)
                    ref_prompt = build_patch_refinement_prompt(
                        target=target,
                        red_exploit_code=red_code,
                        failed_patch=best_cand.patched_source,
                        verification_result=best_res,
                        sandbox_feedback=fb,
                    )
                    raw_r = generator_fn(target, ref_prompt, temp, cand_idx)
                    cand_r = parse_patch_response(raw_r, target.name, candidate_id=f"{cand_id}_r{r_idx}")
                    last_sb["res"] = None
                    res_r = verify_patch(
                        target_name=target.name,
                        original_source=target.source_code,
                        candidate=cand_r,
                        exploit_code=red_code,
                        red_precondition_verified=True,
                        red_verifier=red_verifier,
                        patch_runner=_recording_runner,
                    )
                    if res_r.category == BluePatchCategory.PATCH_INFRA_ERROR:
                        break
                    if (
                        res_r.category == BluePatchCategory.PATCH_VERIFIED
                        or res_r.reward_score > best_res.reward_score
                    ):
                        best_cand = cand_r
                        best_res = res_r
                        best_sb = last_sb["res"]
                        improved_in_refinement = True
                    if best_res.category == BluePatchCategory.PATCH_VERIFIED:
                        break

            total_candidates += 1
            if improved_in_refinement:
                improved_by_refinement_count += 1

            cat_val = best_res.category.value
            category_counts[cat_val] = category_counts.get(cat_val, 0) + 1
            if best_res.category != BluePatchCategory.PATCH_INFRA_ERROR:
                rewards.append(float(best_res.reward_score))

            if target_best_res is None or best_res.reward_score > target_best_res.reward_score:
                target_best_res = best_res
                target_best_code = best_cand.patched_source

            record = DualLoopRecord(
                target_name=target.name,
                red_exploit_code=red_code,
                red_confirmed=best_res.red_precondition_confirmed,
                patch_result=best_res,
            ).model_dump()
            record["run_id"] = active_run_id
            record["candidate_index"] = cand_idx
            record["red_source_trajectory_id"] = red_traj_id
            record["improved_in_refinement"] = improved_in_refinement
            record["patched_source"] = best_cand.patched_source

            out_file = os.path.join(output_dir, f"patch_{active_run_id}_{target.name}_c{cand_idx}.json")
            with open(out_file, "w", encoding="utf-8") as handle:
                json.dump(record, handle, indent=2)
            persisted_paths.append(out_file)

            # Early-stop per target as soon as we achieve a verified patch (+1.0)
            if best_res.category == BluePatchCategory.PATCH_VERIFIED:
                break

        if target_best_res is not None:
            best_patches_by_target[target.name] = {
                "category": target_best_res.category.value,
                "reward_score": target_best_res.reward_score,
                "functional_pass": target_best_res.functional_pass,
                "exploit_blocked": target_best_res.exploit_blocked,
                "reproducibility_confirmed": target_best_res.reproducibility_confirmed,
                "red_source_trajectory_id": red_traj_id,
                "patched_source": target_best_code,
            }
            if target_best_res.category == BluePatchCategory.PATCH_VERIFIED:
                verified_targets.append(target.name)

    return {
        "status": "success",
        "run_id": active_run_id,
        "output_dir": output_dir,
        "total_candidates": total_candidates,
        "persisted_count": len(persisted_paths),
        "persisted_paths": persisted_paths,
        "category_counts": category_counts,
        "verified_targets": verified_targets,
        "improved_by_refinement_count": improved_by_refinement_count,
        "mean_blue_reward": round(sum(rewards) / len(rewards), 4) if rewards else 0.0,
        "best_patches_by_target": best_patches_by_target,
    }
