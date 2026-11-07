# Безопасность исполнения и модель изоляции (Execution Security & Isolation Architecture)

**Документ:** Архитектура изоляции исполнения недоверенного кода и доверенной верификации  
**Проект:** Aegis-RLVR (`NeuBeginner/Agentic-security-RLVR`)  
**Дата:** 07 ноября 2026 г.  
**Ветка:** `feat/verification-core-hardening`  

---

## 1. Контекст угрозы и постановка проблемы

В системе автономного аудита и генерации эксплойтов AI-агенты синтезируют произвольный исходный код на Solidity (`ExploitModule.sol`). 
Исполнение недоверенного кода несет следующие критические риски:
1. **Утечка секретов и ключей:** Оркестратор оперирует API-ключами (`GEMINI_API_KEY`), токенами доступа (`MODAL_TOKEN_ID`, `MODAL_TOKEN_SECRET`), учетными данными облачных провайдеров. Недоверенный код или скомпрометированный компилятор не должен иметь доступа к переменным окружения.
2. **Побег из песочницы (Sandbox Escape):** Использование небезопасных опций Foundry (например, `--ffi`), позволяющих смарт-контрактам вызывать системные утилиты ОС (`bash`, `curl`, чтение произвольных файлов).
3. **DoS и исчерпание ресурсов (Resource Exhaustion):** Бесконечные циклы, исчерпание газа, генерация мегабайтов логов (Log Bomb / stdout flooding), ведущие к падению контейнера по OOM.
4. **Фальсификация результатов (Log Spoofing):** Эксплойт может вызвать `console.log("[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]")` или сымитировать успешный возврат, не нарушая фактического состояния контракта.
5. **Взаимное влияние кандидатов:** Сохранение промежуточных файлов и артефактов между прогонами разных кандидатов.

---

## 2. Границы доверия (Trust Boundaries)

```
+-----------------------------------------------------------------------------------+
| 1. TRUSTED ORCHESTRATION LAYER (Python Orchestrator / Modal Host)                 |
| - API Keys, Modal Secrets, Training Gate, Candidate Lifecycle, GRPO Loss          |
+----------------------------------------+------------------------------------------+
                                         | Sanitized Payload & Parameters
                                         v
+-----------------------------------------------------------------------------------+
| 2. EPHEMERAL WORKER CONTAINER (Modal Ephemeral Function / MicroVM)                |
| - Debian slim, gVisor / container isolation, No GPU, Isolated Temp Directory      |
| - Stripped Environment: No secrets, No cloud tokens, Whitelisted PATH/TMPDIR only |
+----------------------------------------+------------------------------------------+
                                         | Ephemeral Filesystem Mount
                                         v
+-----------------------------------------------------------------------------------+
| 3. HARDENED FOUNDRY EXECUTION SANDBOX (EVM Runner)                                 |
| - foundry.toml: offline=true, ffi=false, gas_limit=30M, fs_permissions='none' ..   |
| - Pre-execution Cheatcode Filter: Blocks vm.*, forge-std/Test.sol, raw addresses  |
| - Output Truncation: Max 1MB log buffer (Anti-Log Bomb)                           |
+-------------------+---------------------------------------+-----------------------+
                    |                                       |
                    v                                       v
+--------------------------------------+  +-----------------------------------------+
| 4. TRUSTED HARNESS (*Harness.t.sol)  |  | 5. UNTRUSTED CANDIDATE (ExploitModule)  |
| - Immutable test harness             |  | - Synthesized by LLM / Mutator          |
| - Initial state snapshot             |  | - Unprivileged caller                   |
| - Post-condition balance checks      |  | - Must not have cheatcodes or root      |
| - Emits SecurityInvariantBreached    |  | - State mutations subject to EVM rules  |
+-------------------+------------------+  +-----------------------------------------+
                    |
                    v
+-----------------------------------------------------------------------------------+
| 6. TRUSTED EVM STATE ORACLE (core/evm_oracle.py)                                  |
| - Cryptographic State Hashing: initial_state_hash, final_state_hash               |
| - Formal Invariant Evaluation: Vault Solvency, ERC-4626 Dilution, Non-Zero Shares |
| - Anti-Spoofing Gate: Rejects bare text markers unless verified by State Delta   |
+-----------------------------------------------------------------------------------+
```

---

## 3. Защитные механизмы и подтвержденные гарантии

### 3.1. Очистка переменных окружения (`build_sanitized_environment`)
- **Реализация:** `sandbox/runner.py` формирует окружение на основе строгого белого списка (`PATH`, `TMPDIR`, `LANG`).
- **Блокировка секретов:** Любые переменные, содержащие паттерны `KEY`, `TOKEN`, `SECRET`, `AUTH`, `PASS`, `MODAL_`, `GEMINI_`, `AWS_`, `GITHUB_`, `SSH_`, принудительно удаляются.
- **Подтверждение тестом:** `tests/test_verification_core_and_oracle.py::test_sanitized_environment_strips_sensitive_keys` (PASS).

### 3.2. Конфигурация Foundry (`foundry.toml`)
- **`offline = true`:** Не позволяет Foundry разрешать удалённые зависимости в offline-режиме. Это не эквивалент сетевой изоляции всего процесса или Modal worker.
- **`ffi = false`:** Полностью отключает внешние вызовы (Foreign Function Interface) на уровне компилятора и рантайма EVM.
- **`fs_permissions = [{ access = "none", path = ".." }, { access = "read-write", path = "./" }]`:** Запрещает выход в родительские каталоги `/root`, `/etc`, `/vol`.
- **`gas_limit = 30000000`:** Ограничивает объем вычислительных ресурсов на один тест.

### 3.3. Защита от Log Bombing (`truncate_log_output`)
- **Лимит:** Максимум 1 МБ (1024 * 1024 байт) на поток `stdout` и `stderr`.
- **Поведение:** При превышении лимита вывод обрезается с маркером `[LOG_TRUNCATED: Output exceeded safe quota of 1MB]`.
- **Подтверждение тестом:** `tests/test_verification_core_and_oracle.py::test_log_output_truncation_quota` (PASS).

### 3.4. Блокировка привилегий и чит-кодов (`detect_prohibited_cheatcodes`)
- **Реализация:** Предварительный лексический и строковый анализ отсекает использование `vm.*`, `forge-std/Vm.sol`, `forge-std/Test.sol` и сервисного адреса чит-кодов `0x7109709ECfa91a80626fF3989D68f67F5b1DD12D`.
- **Категория при нарушении:** Немедленный статус `CHEATCODE_DETECTED`, штраф `reward = -1.0`, прогон в Foundry блокируется.
- **Подтверждение тестом:** `tests/test_verification_core_and_oracle.py::test_cheatcode_detection_blocks_sandbox_escape` (PASS).

### 3.5. Верификация состояния: fail-closed до появления аутентифицированного адаптера

**Текущая реализация не доказывает происхождение события из доверенного harness.** Foundry `decoded_logs` возвращает декодированные представления логов; строка с именем `SecurityInvariantBreached` или `[ORACLE_SNAPSHOT:...]` не является достаточным доказательством адреса-эмиттера и может быть воспроизведена недоверенным кандидатом.

Поэтому текущая ветка намеренно:
- не принимает event/log strings как доказательство нарушения;
- не синтезирует начальное или конечное состояние при отсутствии аутентифицированных снимков;
- возвращает `UNVERIFIED`, когда нет независимых pre/post-state данных;
- переводит такой результат в `INFRA_ERROR` для reward pipeline с нейтральным reward 0.0;
- не допускает такой результат в обучающую выборку как подтверждённый эксплойт.

Для положительного reward нужен отдельный доверенный адаптер: он должен получать состояние EVM независимо от вывода кандидата, связывать его с конкретным target/run, проверять идентичность проверяемого harness и передавать типизированное доказательство. Это незавершённая инженерная задача, а не гарантия текущего парсера логов.

### 3.6. Независимый структурированный Replay Verifier

Replay-код умеет сравнивать наборы нарушенных инвариантов между прогонами, но он не устраняет отсутствие доверенного источника исходного доказательства. Replay разрешается считать подтверждением только после получения валидного доказательства первого прогона и доказательства повторного прогона. Повтор одинаковой строки лога подтверждением не является.

### 3.6. Независимый структурированный Replay Verifier
- **Проверка:** Повторный запуск в чистом контейнере/директории с фиксацией `initial_state_hash`, `final_state_hash` и сравнением списка нарушенных инвариантов.
- **Гарантия:** Если в повторном прогоне нарушен другой инвариант или инвариант не нарушен, replay помечается `INVARIANT_MISMATCH` или `FAILED` и не допускается к категории `EXPLOIT_CONFIRMED`.
- **Подтверждение тестом:** `tests/test_verification_core_and_oracle.py::test_independent_replay_structured_lifecycle` (PASS).

---

## 4. Ограничения и оставшиеся риски

1. **Изоляция на уровне хоста (Windows Local vs Modal Linux):**
   - В локальном режиме (Windows) изоляция обеспечивается через `tempfile.TemporaryDirectory()`, ограничение окружения `os.environ` и параметры `foundry.toml`. Изоляция зависит от фактической границы Modal worker/container и настроек запуска. `tempfile`, очищенное окружение и параметры Foundry сами по себе не создают отдельную OS sandbox.
2. **0-day уязвимости в бинарнике `forge`:**
   - Если в самом компиляторе `solc` или бинарнике `forge` будет обнаружен эксплойт переполнения буфера или удаленного исполнения кода, защита опирается на контейнерный слой Modal. В локальном запуске рекомендуется использовать Docker/WSL2.
3. **Лимиты оперативной памяти процессов:**
   - В Modal лимит памяти на контейнер задается через `memory=config.SANDBOX_MEMORY_MB` (2048 MB). В локальном Windows subprocess ограничение памяти через OS Job Objects не активно по умолчанию, контроль осуществляется через таймаут subprocess.

---

*Документ актуализирован в рамках реализации Этапа 1 (Verification Core).*
