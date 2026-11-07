# Архитектура пайплайна гипотез и обратной связи (Hypothesis-Driven Pipeline & Feedback Loop)

**Документ:** Спецификация связки Auditor → Hypothesis Manager → Exploit Generator → Verification → Replay  
**Проект:** Aegis-RLVR (`NeuBeginner/Agentic-security-RLVR`)  
**Дата:** 07 ноября 2026 г.  
**Ветка:** `feat/verification-core-hardening`  

---

## 1. Контекст проблемы и устранение архитектурного разрыва

В исходной реализации `modal_app.py` существовал разрыв между аудитом и генерацией:
```python
findings = llm_agent.audit_target_contract.remote(target.model_dump())
...
# Findings выводились в print(), но в generator передавался только сырой target:
p_dict = llm_agent.generate_solidity_exploit.remote(target.model_dump(), temperature=temp)
```
Результаты статического анализа и аудита игнорировались генератором, который был вынужден заново с нуля "угадывать" уязвимости смарт-контракта без контекста конкретных функций, векторов атак и предварительных условий.

В рамках модернизации внедрен **Hypothesis Manager** (`core/hypothesis_manager.py`), который трансформирует неструктурированные сообщения моделей и статических анализаторов в типизированные, дедуплицированные и приоритизированные гипотезы.

---

## 2. Архитектура замкнутого цикла (Closed Feedback Loop)

```
+-----------------------------------------------------------------------------------+
| 1. AUDIT & STATIC ANALYSIS LAYER                                                  |
| - Slither AST Parser (target.slither_findings)                                    |
| - Qwen-Audit 30B Agent (findings = audit_target_contract.remote())                |
+----------------------------------------+------------------------------------------+
                                         | Ingest raw findings
                                         v
+-----------------------------------------------------------------------------------+
| 2. HYPOTHESIS MANAGER (core/hypothesis_manager.py)                                |
| - Normalization: maps to canonical classes (Reentrancy, ERC4626Inflation, etc.)   |
| - Deduplication: merges duplicates on (class, contract, function)                 |
| - Prioritization: ranks by Severity (Critical > High > Med) and Confidence       |
| - Lifecycle: PROPOSED -> NORMALIZED -> PRIORITIZED                                |
+----------------------------------------+------------------------------------------+
                                         | Top Prioritized Hypotheses
                                         v
+-----------------------------------------------------------------------------------+
| 3. EXPLOIT GENERATOR & MUTATOR (core/llm_generator.py & modal_app.py)              |
| - Inputs: Target + Structured Hypothesis + Expected Invariant + Failed History    |
| - Generates: ExploitModule targeting specific hypothesis vector                   |
| - Lifecycle: -> GENERATED                                                         |
+----------------------------------------+------------------------------------------+
                                         | ExploitPayload
                                         v
+-----------------------------------------------------------------------------------+
| 4. ISOLATED EVM EXECUTION & TRUSTED STATE ORACLE (sandbox/runner.py)              |
| - Executes in isolated Foundry environment with stripped secrets                  |
| - TrustedEVMStateOracle verifies state deltas and mathematical invariants         |
| - Lifecycle: -> TESTED                                                            |
+-------------------+-----------------------------------+---------------------------+
                    |                                   |
           (State Breach Detected)              (Safe Run / Revert)
                    |                                   |
                    v                                   v
+--------------------------------------+  +-----------------------------------------+
| 5. INDEPENDENT REPLAY VERIFIER       |  | 6. REFINEMENT & FAILURE MUTATION        |
| - Fresh ephemeral EVM sandbox        |  | - Refinement receives failure trace     |
| - Asserts exact invariant match      |  | - Hypothesis Manager updates attempts   |
| - CONFIRMED -> status='confirmed'    |  | - Exhausted (>=3 fails) -> 'rejected'   |
+-------------------+------------------+  +-----------------------------------------+
                    |
                    v
+-----------------------------------------------------------------------------------+
| 7. PERSISTENCE & RLVR DATASET INTEGRATION                                         |
| - Confirmed exploits recorded with hypothesis_id and full provenance              |
| - Safe runs and rejected candidates archived with negative reward                 |
+-----------------------------------------------------------------------------------+
```

---

## 3. Модель данных гипотезы (`VulnerabilityHypothesis`)

Схема определена в `core/schemas.py`:
- `hypothesis_id`: Уникальный детерминированный идентификатор (например, `hyp_Vault_reentr_1`).
- `target_id`: Имя целевого смарт-контракта.
- `source_finding_id`: Идентификатор источника (`qwen-audit_1`, `slither_1`).
- `vulnerability_class`: Стандартизированный класс уязвимости (`Reentrancy`, `ERC4626Inflation`, `AccessControl`, `OracleManipulation` и др.).
- `affected_contract`: Контракт, подверженный атаке.
- `affected_function`: Конкретная функция, содержащая уязвимость (например, `withdrawAll`).
- `attack_preconditions`: Список предусловий (баланс атакующего, необходимые роли, предварительные депозиты).
- `attack_sequence`: Последовательность шагов эксплуатации.
- `expected_invariant`: Ожидаемый к нарушению инвариант (например, `Depositor Solvency Coverage`).
- `severity`: Критичность (`Critical`, `High`, `Medium`, `Low`).
- `confidence`: Оценка уверенности (от 0.0 до 1.0).
- `validation_status`: Текущий статус в цикле верификации.
- `attempt_count`: Количество сгенерированных и протестированных кандидатов.
- `last_error`: Диагностический след последней неудачи.

---

## 4. Статусная модель и переходы (Lifecycle Transitions)

1. `proposed` / `normalized`: Исходная находка извлечена и приведена к единому формату.
2. `prioritized`: Гипотеза прошла дедупликацию и взвешивание по критичности; готова для генератора.
3. `generated`: По гипотезе сформирован один или более `ExploitPayload`.
4. `tested`: Эксплойт выполнен в EVM песочнице:
   - Если зафиксирован предварительный пробой (`INVARIANT_BREACH_UNREPLAYED`), гипотеза ожидает подтверждения Replay.
   - Если произошел реверт или безопасное выполнение (`SAFE_RUN`), счетчик `attempt_count` инкрементируется.
5. `confirmed`: Независимый Replay в чистом контейнере подтвердил нарушение того же инварианта со 100% воспроизводимостью.
6. `rejected`: После исчерпания допустимого числа попыток (по умолчанию >=3) гипотеза признается ложноположительной или невоспроизводимой.
7. `inconclusive`: Ошибка инфраструктуры или таймаут.

---

## 5. Подтверждение тестами

1. `tests/test_hypothesis_pipeline.py::test_classify_vulnerability_categories`: Корректная классификация 7+ классов уязвимостей.
2. `tests/test_hypothesis_pipeline.py::test_deduplicate_and_rank_hypotheses`: Объединение дубликатов с объединением последовательностей атак.
3. `tests/test_hypothesis_pipeline.py::test_prompt_includes_hypothesis_and_failures`: Инъекция гипотез и следов неудач в промпт генератора.
4. `tests/test_hypothesis_pipeline.py::test_feedback_loop_status_transitions`: Корректный переход `prioritized -> tested -> confirmed`.
5. `tests/test_hypothesis_pipeline.py::test_feedback_loop_rejection_after_exhaustion`: Автоматический перевод в `rejected` при трех неудачах.

---

*Документ актуализирован в рамках реализации Этапа 2 (Hypothesis-Driven Pipeline).*
