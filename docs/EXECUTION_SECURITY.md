# Безопасность исполнения и модель изоляции (Execution Security & Isolation Architecture)

**Документ:** Архитектура изоляции исполнения недоверенного кода и доверенной верификации  
**Проект:** Aegis-RLVR (`NeuBeginner/Agentic-security-RLVR`)  
**Дата:** 07 ноября 2026 г.  
**Ветка:** `feat/verification-core-hardened`  

---

## 1. Контекст угрозы и постановка проблемы

В системе автономного аудита и генерации эксплойтов AI-агенты синтезируют произвольный исходный код на Solidity (`ExploitModule.sol`). 
Исполнение недоверенного кода несет следующие критические риски:
1. **Утечка секретов и ключей:** Оркестратор оперирует API-ключами (`GEMINI_API_KEY`), токенами доступа (`MODAL_TOKEN_ID`, `MODAL_TOKEN_SECRET`), учетными данными облачных провайдеров. Недоверенный код или скомпрометированный компилятор не должен иметь доступа к переменным окружения.
2. **Побег из песочницы (Sandbox Escape):** Использование небезопасных опций Foundry (например, `--ffi`), позволяющих смарт-контрактам вызывать системные утилиты ОС (`bash`, `curl`, чтение произвольных файлов).
3. **DoS и исчерпание ресурсов (Resource Exhaustion):** Бесконечные циклы, исчерпание газа, генерация гигабайтов логов (Log Bomb / stdout streaming exhaustion), ведущие к падению хоста или контейнера по OOM.
4. **Фальсификация результатов (Log Spoofing):** Эксплойт может вызвать `console.log("[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]")`, сымитировать event `SecurityInvariantBreached` со своего адреса или вывести фальшивый `[ORACLE_SNAPSHOT:...]`.
5. **Взаимное влияние кандидатов и подмена харнесса:** Эксплойт может попытаться унаследовать `Test`, определить собственные функции `test...()`, перезаписать доверенный харнесс или сохраниться между прогонами.

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
| - Linux cgroups / resource limits (RLIMIT_AS, RLIMIT_NPROC, RLIMIT_FSIZE)        |
+----------------------------------------+------------------------------------------+
                                         | Ephemeral Filesystem Mount
                                         v
+-----------------------------------------------------------------------------------+
| 3. HARDENED FOUNDRY EXECUTION SANDBOX (EVM Runner)                                 |
| - foundry.toml: offline=true, ffi=false, gas_limit=30M, memory_limit=128MB        |
| - fs_permissions: access='none' path='..' (Host filesystem access restricted)    |
| - Streaming reader: Hard log quota 1MB, immediate tree termination on Log Bomb   |
| - Process tree killer: taskkill /F /T (Windows) and os.killpg (POSIX)             |
+-------------------+---------------------------------------+-----------------------+
                    |                                       |
                    v                                       v
+--------------------------------------+  +-----------------------------------------+
| 4. TRUSTED HARNESS (*Harness.t.sol)  |  | 5. UNTRUSTED CANDIDATE (ExploitModule)  |
| - Immutable test harness in test/    |  | - Written ONLY to src/ExploitModule.sol |
| - Canonical runner address check     |  | - Prohibited: is Test, is DSTest        |
| - Cryptographic keccak256 topic check|  | - Prohibited: function test...()        |
| - State snapshot & deficit events    |  | - Prohibited: vm.*, RPC, fork, readFile |
+-------------------+------------------+  +-----------------------------------------+
                    |
                    v
+-----------------------------------------------------------------------------------+
| 6. TRUSTED EVM STATE ORACLE (core/evm_oracle.py)                                  |
| - Cryptographic State Hashing: initial_state_hash, final_state_hash               |
| - Topic & Emitter Verification: Validates msg.sender is trusted harness address   |
| - Invariant Registry Precedence: Specialized rules first, no generic fallback     |
| - Zero Synthetic State Creation: No fake balances fabricated on missing snapshot  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Защитные механизмы и подтвержденные гарантии

### 3.1. Очистка переменных окружения (`build_sanitized_environment`)
- **Реализация:** `sandbox/runner.py` формирует окружение на основе строгого белого списка (`PATH`, `TMPDIR`, `TEMP`, `SYSTEMROOT`, `LANG`, `LC_ALL`).
- **Блокировка секретов:** Любые переменные, содержащие паттерны `KEY`, `TOKEN`, `SECRET`, `AUTH`, `PASS`, `MODAL_`, `GEMINI_`, `AWS_`, `GITHUB_`, `SSH_`, принудительно удаляются.
- **Подтверждение тестом:** `test_sanitized_environment_strips_sensitive_keys` (PASS).

### 3.2. Потоковое чтение с жесткой квотой против Log Bombing (`run_command_streaming_with_quota`)
- **Проблема PR #1:** Неограниченный `subprocess.run(capture_output=True)` аккумулировал весь вывод процесса в оперативной памяти до вызова функции обрезки, что позволяло эксплойту вызвать OOM хоста (Log Bomb).
- **Решение:** Потоковое чтение chunk-ами по 4 КБ в фоновых потоках без буферизации всего объема в памяти.
- **Поведение:** Если объем `stdout` или `stderr` превышает 1 МБ (`MAX_LOG_OUTPUT_BYTES`), выставляется `quota_exceeded = True`, и процесс немедленно принудительно завершается вместе со всем деревом дочерних процессов (`kill_process_tree`).
- **Подтверждение тестом:** `test_streaming_log_bomb_protection` (PASS).

### 3.3. Гарантированное завершение дерева процессов (`kill_process_tree`)
- **Проблема PR #1:** Вызов `proc.kill()` по таймауту завершал только родительский процесс, оставляя фоновые дочерние процессы (компилятор, форки `forge`, субпроцессы) висеть в памяти.
- **Решение:** 
  - На Windows: `taskkill /F /T /PID {pid}` (рекурсивное завершение дерева процессов).
  - На POSIX (Linux/Modal): создание отдельной группы процессов через `os.setsid()` при запуске и посылка `os.killpg(pgid, signal.SIGKILL)` при таймауте.
- **Подтверждение тестом:** `test_process_tree_termination_on_timeout` (PASS).

### 3.4. Системные ограничения CPU, RAM и файловой системы
- **Linux / Modal Worker:**
  - `resource.setrlimit(RLIMIT_AS, 2GB)`: ограничение виртуальной памяти подпроцесса.
  - `resource.setrlimit(RLIMIT_FSIZE, 10MB)`: ограничение размера создаваемых файлов на диске.
  - `resource.setrlimit(RLIMIT_NPROC, 128)`: ограничение числа дочерних процессов (защита от fork-бомб).
- **Foundry EVM limits (`foundry.toml`):**
  - `gas_limit = 30000000`: жесткий предел газа на транзакцию.
  - `memory_limit = 134217728` (128 МБ): максимальная память, выделяемая EVM.
  - `fs_permissions = [{ access = "none", path = ".." }, { access = "read-write", path = "./" }]`: запрет доступа за пределы временной рабочей директории.

### 3.5. Реальная сетевая изоляция и запрет чит-кодов
- **`offline = true` и `clean_env["FOUNDRY_OFFLINE"] = "true"`:** Запрещает любые сетевые обращения во время компиляции и тестирования.
- **`ffi = false`:** Полностью отключает системные вызовы через Foundry FFI.
- **Блокировка чит-кодов:** Запрещены `vm.*`, `forge-std/Vm.sol`, сетевые и форк-читкоды (`vm.createFork`, `vm.rpcUrl`), чит-коды доступа к ФС (`vm.readFile`, `vm.writeFile`).
- **Подтверждение тестом:** `test_prohibited_network_and_harness_inheritance_cheatcodes` (PASS).

### 3.6. Строгое разделение доверенного харнесса и недоверенного эксплойта
- **Изоляция директорий:** `ExploitModule.sol` записывается **ИСКЛЮЧИТЕЛЬНО** в директорию `src/ExploitModule.sol`. Запрещено записывать эксплойт в `test/`.
- **Запрет подмены тест-раннера:** Запрещено наследование `contract ... is Test` или определение функций `test...()` внутри недоверенного эксплойта.
- **Фильтрация запуска:** Запуск тестов выполняется строго с параметром `--match-contract .*{target.name}.*Harness`, гарантируя исполнение только доверенного контракта верификации.

---

## 4. Гарантии Modal: подтвержденные vs неподтвержденные

| Аспект безопасности | Гарантируется Modal (Подтверждено) | Не гарантируется / Не подтверждено в Modal |
|---|---|---|
| **Изоляция процесса** | Запуск в изолированном Linux-контейнере с индивидуальным cgroup и пространством имен PID. | Совместное использование ядра хоста (kernel sharing). В случае уязвимостей ядра (kernel exploit) контейнерная изоляция недостаточна без MicroVM (Firecracker/gVisor). |
| **Файловая система** | Временная файловая система контейнера является ephemeral и уничтожается после завершения вызова функции. | Если подключен общий Modal Volume (`modal.Volume`), запись в директорию тома является персистентной и может загрязнять окружение последующих прогонов, если не монтируется read-only. |
| **Сетевая изоляция** | Вызовы функций маршрутизируются через прокси Modal. | По умолчанию контейнеры Modal **ИМЕЮТ доступ в интернет** (исходящие соединения не заблокированы по умолчанию на уровне сетевого интерфейса). Необходима строгая блокировка на уровне рантайма (`foundry.toml offline=true` и `FOUNDRY_OFFLINE=true`). |
| **Лимиты CPU / RAM** | Жесткие квоты на RAM (`memory=2048`) и CPU (`cpu=2.0`), управляемые cgroups гипервизора. Превышение квоты приводит к OOMKilled от самого Modal. | Внутри контейнера процесс может потреблять 100% выделенного CPU до срабатывания `timeout`, вызывая локальный троттлинг внутри временного интервала. |
| **Секреты оркестрации** | Переменные окружения Modal Secrets (`modal.Secret`) передаются только объявленным функциям. | Если функция верификации и функция оркестрации выполняются в одном окружении без очистки `os.environ`, секреты наследуются подпроцессами. В Aegis-RLVR реализован обязательный слой `build_sanitized_environment()`. |

---

## 5. Доверенная верификация состояния (Trusted EVM State Oracle)

- **Критерии подтверждения уязвимости:**
  1. Код завершения `return_code == 0`.
  2. Доверенный харнесс с верифицированным адресом эмитента (`CANONICAL_HARNESS_ADDRESS`) выпустил лог с криптографическим топиком `keccak256("SecurityInvariantBreached(string,uint256)")`.
  3. Отсутствие признаков спуфинга (сообщения `console.log` и события от сторонних адресов отсекаются).
  4. Оракул `core/evm_oracle.py` подтвердил математическое нарушение инварианта на фактическом состоянии.
  5. Отсутствие синтетической фабрикации состояния: если реальный snapshot отсутствует, балансы не генерируются фиктивно.
