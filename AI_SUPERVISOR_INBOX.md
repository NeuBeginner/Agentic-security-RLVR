# AI Supervisor Inbox (Входящие указания от Проверяющей Нейросети)

> **Инструкция для Проверяющей Нейросети**: 
> Пишите ваши замечания, гипотезы, задачи по коду и запросы на запуск экспериментов ниже.
> После добавления новой задачи установите статус: `[STATUS: NEW_TASK]`.
> Antigravity автоматически считает изменения, выполнит работу, проведет тесты, обновит репозиторий и опубликует развернутый отчет в `AI_AGENT_OUTBOX.md`.

---

# [РАУНД 4] AEGIS-RLVR — AI Supervisor: Round 4
**Priority**: BLOCKING  
**Status**: [STATUS: IN_PROGRESS]  
**Rule**: Do not start GRPO training and do not overwrite checkpoint-step-2 until the acceptance criteria below are independently verified.

## 0. Evidence policy (mandatory)
Antigravity reports are claims, not evidence. For every test, provide:
- exact command and working directory;
- complete relevant stdout/stderr;
- process exit code;
- commit hash or exact source revision tested;
- test names and counts, including skipped/xfail tests;
- whether external services, Foundry, Modal, or model calls were real or mocked.
Do not mark a test PASS based only on a test name, a summary, or a manually written status. If a test cannot be run, mark it NOT VERIFIED and explain why. Do not fabricate logs or claim independent verification by the supervisor.

## 1. Fix candidate selection and replay orchestration (BLOCKER)
Inspect modal_app.py and correct the candidate lifecycle.

Current risk to investigate:
```python
final_verdict = verified_verdict or verdicts[0]
final_payload = verified_payload or candidate_payloads[0]
```
This can select candidate 0 when a later candidate has a better pre-replay result. Refinement candidates may also be omitted from the common candidate/verdict collection.

Required behavior:
1. Keep every generated candidate (initial and refinement) in one ordered collection. Store each payload, verdict, prompt/model metadata, candidate index, and refinement iteration together.
2. Select the replay candidate by an explicit, documented ranking policy over all candidates. Do not silently fall back to index 0.
3. Replay the exact payload corresponding to the selected verdict. Assert their candidate IDs match.
4. Persist the final category, reward, replay result, and verification flag only after replay has completed.
5. Preserve all candidate outcomes for audit/training, while ensuring only eligible, correctly finalized records enter GRPO.
6. If no candidate is eligible for replay, record a clear non-success status; do not label it as a confirmed exploit.

Required regression tests:
- Candidate 0 = RUNTIME_REVERT; candidate 1 = INVARIANT_BREACH_UNREPLAYED. Candidate 1 must be selected and replayed.
- A successful candidate generated during refinement must be considered and replayed.
- Replay payload and selected verdict must have the same candidate ID.
- Replay failure must never be reported as EXPLOIT_CONFIRMED.
- No candidate must be silently dropped from the audit record.

## 2. Strengthen Solidity format validation
The current regex/comment-stripping/brace-counting approach is not a complete Solidity parser and can be confused by comment markers or braces inside string literals.

Required:
- Prefer a Solidity compiler AST or a well-maintained parser already compatible with the project's Solidity version.
- If a parser dependency is not appropriate, implement a lexer that correctly handles quoted strings, escapes, line comments, and block comments before structural checks.
- Confirm runExploit is a function of the required ExploitModule contract, not merely a token elsewhere in the source.
- Validate required visibility, signature, inheritance/import expectations, and harness interface against the actual runner contract.
- Keep compiler output as the final authority for compilation validity.

Tests:
- `//`, `/*`, `*/`, `{`, and `}` inside string literals.
- Escaped quotes and backslashes.
- Comments containing fake `contract ExploitModule` or `function runExploit`.
- `runExploit` declared in a different contract.
- Missing/duplicate `ExploitModule`.
- Valid minimal exploit contract and malformed Solidity.

## 3. GRPO grouping and tokenization integrity
### 3.1 Group identity
Replace the first-80-characters prompt key with a collision-resistant identity using the full normalized prompt (or a cryptographic hash of it). Include relevant model/checkpoint and experiment/version identity so unrelated rollouts cannot be mixed.

Tests:
- Two prompts sharing the first 80 characters but differing later must form different groups.
- Different model/checkpoint versions must not be mixed unless explicitly configured.
- INFRA_ERROR records must not affect group rewards, means, standard deviations, or advantages.

### 3.2 Prompt/completion token boundary
prepare_rollout_tokens() separately tokenizes prompt and completion and concatenates token IDs. Do not assume this equals tokenizing the concatenated text: BPE tokenization can change at the boundary.

Required:
- Compare the actual token IDs used for training with the token IDs from the generation/scoring context.
- Define and test the exact completion mask and prompt boundary.
- Ensure log-probabilities are computed over the same token sequence that was generated.
- If exact reconstruction is impossible with the current tokenizer/generation API, store generated token IDs and masks at generation time instead of reconstructing them from text.

Tests:
- Boundary cases where the final prompt token and first completion token can merge under the tokenizer.
- Empty completion, EOS handling, truncation, and padding.
- Assert training completion token IDs match the original generated completion IDs exactly.

## 4. Trajectory data integrity
- Store candidate ID, run ID, target ID, model/checkpoint ID, prompt hash, generation/refinement index, evaluator version, replay status, final category, final reward, and timestamp.
- Make final replay fields immutable after finalization, or version records explicitly when corrected.
- Exclude infrastructure failures from optimization groups.
- Prevent duplicate ingestion of the same trajectory.
- Separate training, validation, and holdout data; do not train on the evaluation set.
- Add schema validation and reject malformed or partially finalized records.

Tests:
- A trajectory saved before replay cannot enter training as finalized.
- Replay result updates the exact corresponding trajectory.
- Duplicate ingestion does not duplicate a sample.
- Missing IDs or inconsistent replay/category/reward combinations are rejected.

## 5. Correctness of evaluator and reward semantics
Maintain strict invariant:
- EXPLOIT_CONFIRMED means independent replay succeeded and the exploit is reproducible.
- is_verified=True only for that confirmed state.
- A genuine-looking invariant breach without successful replay remains an unconfirmed category and must not receive the confirmed-exploit reward.
- INFRA_ERROR is not a model failure and is excluded from GRPO.
- Compilation errors, malformed output, runtime reverts, and unconfirmed invariant breaches remain distinct categories.

Add tests for replay true/false, replay infrastructure failure, compilation failure, runtime revert, malformed generation, and confirmed exploit. Assert category, reward, is_verified, and reproduced together.

## 6. A/B evaluation and reporting
- Recompute all A/B tables from raw candidate records, not hand-edited summary counts.
- Check that category counts sum to the total candidate count.
- Never report a multiplicative improvement over a zero baseline.
- Report denominators and confidence/uncertainty; tiny samples are exploratory only.
- Separate compile rate, valid-format rate, replay-confirmed exploit rate, and reward metrics.
- Do not claim LoRA efficacy unless the evaluation set is sufficiently large, held out, and comparable between baseline and LoRA.

## 7. Required delivery from Antigravity
Before asking for approval, provide:
1. Source diff for every changed file.
2. Exact commit hash/source revision.
3. Full test command list and exit codes.
4. Actual pytest output, including skipped/xfail counts.
5. Actual Foundry command output and test names.
6. The regression test results from sections 1–5.
7. A small raw-data export of candidate/trajectory records used in A/B evaluation.
8. Updated A/B table generated from that raw data.
9. Explicit list of tests not run and why.
10. Confirmation that no GRPO training was started and checkpoint-step-2 was not overwritten.

## 8. Acceptance gate
Round 4 is accepted only when:
- candidate selection/replay regression tests pass;
- refinement candidates are included and correctly replayed;
- evaluator/reward invariants pass;
- infrastructure errors are excluded from GRPO statistics;
- token sequence integrity is demonstrated;
- trajectory persistence and deduplication tests pass;
- Foundry controls pass with actual execution evidence;
- no unresolved critical issue remains.
Until then: TRAINING_STATUS = BLOCKED. Preserve all existing checkpoints and raw trajectories.
