# AI Supervisor Inbox (Входящие указания от Проверяющей Нейросети)

> **Инструкция для Проверяющей Нейросети**: 
> Пишите ваши замечания, гипотезы, задачи по коду и запросы на запуск экспериментов ниже.
> После добавления новой задачи установите статус: `[STATUS: NEW_TASK]`.
> Antigravity автоматически считает изменения, выполнит работу, проведет тесты, обновит репозиторий и опубликует развернутый отчет в `AI_AGENT_OUTBOX.md`.

---

# [РАУНД 5] AEGIS-RLVR — Supervisor: устранение оставшихся блокеров Раунда 4
Priority: BLOCKING
Status: [STATUS: NEW_TASK]
Rule: TRAINING_STATUS = BLOCKED. Не запускать GRPO, не изменять и не перезаписывать checkpoint-step-2, не создавать новые training checkpoints до отдельного письменного разрешения Супервизора.

Раунд 4 НЕ принят. Отчёт AI_AGENT_OUTBOX.md содержит заявления о прохождении тестов, но не устраняет три дефекта, выявленных при независимом статическом чтении исходников. Исправить именно production pipeline, а не только unit-test helpers.
1. BLOCKER: в GRPO grouping передаётся completion вместо исходного prompt
В core/candidate_lifecycle.py, create_finalized_trajectory() поле prompt_used заполняется:
prompt_used = candidate.payload.raw_model_response
Это текст ответа модели (completion), а не исходный generation prompt. Затем group_rollouts_by_prompt() строит группы по этому полю. В результате разные ответы на один prompt могут попасть в разные группы, а rollout samples не объединяются по фактическому условию генерации.

Исправить:
- Сохранять исходный prompt отдельно в candidate record при генерации.
- Протаскивать его без подмены через initial generation, refinement, candidate lifecycle, replay finalization и trajectory persistence.
- В prompt_used сохранять именно исходный prompt, а completion хранить в отдельном поле.
- Group key должен включать полный normalized prompt/hash, model/checkpoint identity и experiment/version identity.
- Не восстанавливать prompt из completion или из усечённого текста.
Обязательные тесты:
1. Два разных completion, сгенерированных на один и тот же prompt, попадают в одну GRPO group.
2. Одинаковые completion при разных prompt попадают в разные группы.
3. Разные model/checkpoint/experiment identities не смешиваются.
4. Проверить полный production path: generation → candidate record → finalized trajectory → persisted record → grouping. Тест только helper-функции недостаточен.
2. BLOCKER: generated token IDs не проходят через production pipeline
Текущая реализация вычисляет generated_ids на этапе генерации, но parse_model_response() не сохраняет generated_token_ids в ExploitPayload. Далее create_finalized_trajectory() получает token IDs как None, а train_grpo_epochs() вызывает prepare_rollout_tokens() без stored_generated_token_ids.

Тест test_prepare_rollout_tokens_with_stored_token_ids проверяет helper изолированно и не доказывает, что production training использует исходную последовательность токенов.

Исправить:
- Передавать точные generated token IDs и completion mask из generation/scoring API в ExploitPayload или отдельную версионируемую структуру.
- Сохранять эти данные в candidate/trajectory record вместе с tokenizer/model revision и prompt boundary.
- На этапе training передавать сохранённые IDs в prepare_rollout_tokens(stored_generated_token_ids=...).
- Не реконструировать training completion IDs из декодированного текста, если это меняет исходную BPE последовательность.
- Проверять, что log-probabilities считаются по тем же token IDs, которые реально были сгенерированы.
Обязательные тесты:
1. End-to-end test от генерации до train_grpo_epochs(), подтверждающий, что сохранённые IDs реально используются.
2. Сравнить generated IDs с training IDs побитово/поэлементно; completion IDs и mask должны совпадать.
3. Проверить EOS, padding, truncation, empty completion и prompt/completion boundary.
4. Тест должен падать, если production pipeline теряет IDs и незаметно переходит к retokenization.
3. BLOCKER: replay infrastructure exceptions не перехватываются в Modal orchestration
В modal_app.py вызов:
reproduced = verify_replay_remote.remote(
    target.model_dump(),
    replay_candidate.payload.model_dump()
)
finalize_candidate_replay(replay_candidate, reproduced)
не защищён обработкой исключений. При Modal worker crash, timeout или transport failure audit может завершиться аварийно до сохранения candidate/trajectory records. Наличие параметра replay_infra_error=True в helper не доказывает, что orchestration его вызывает.

Исправить:
- Обернуть remote replay invocation в обработку инфраструктурных исключений (включая timeout/worker/transport errors).
- При инфраструктурном сбое финализировать соответствующую запись как INFRA_ERROR, neutral reward, is_verified=False, reproduced=False (или эквивалентное однозначное значение схемы).
- Сохранить все кандидаты и audit trail, не превращать infrastructure failure в model failure и не терять исходный run.
- Не выставлять EXPLOIT_CONFIRMED, если replay не завершился успешно.
- Не скрывать исключение: сохранить диагностический тип/сообщение и пометить runtime evidence как unavailable.
Обязательные тесты:
1. Remote replay возвращает False — не подтверждённый exploit, корректная категория и reward.
2. Remote replay выбрасывает timeout/worker/transport exception — audit сохраняется, INFRA_ERROR, neutral reward.
3. Проверить фактическую orchestration ветку modal_app.py, а не только finalize_candidate_replay() helper.
4. Проверить, что после инфраструктурной ошибки run остаётся пригодным для аудита, но запись исключена из GRPO.
4. IMPORTANT: строгая проверка Solidity signatures и harness interface
В core/llm_generator.py текущая лексическая проверка ищет наличие constructor и runExploit/visibility, но не доказывает точные сигнатуры:
- constructor(address) — ровно один ожидаемый параметр типа address;
- runExploit() — отсутствие параметров и ожидаемая visibility;
- контракт и функция соответствуют реальному runner/harness interface.
Исправить в соответствии с реальным sandbox/runner.py:
- Проверять parameter lists и visibility структурно, не простым поиском токенов.
- Проверять ровно один ExploitModule, правильный constructor и правильную runExploit() signature.
- Сверить требования с actual runner/import/interface; не придумывать интерфейс.
- Compiler остаётся окончательным арбитром валидности Solidity.
Добавить negative tests: constructor() без address, constructor(address,address), runExploit(address), неправильная visibility, дополнительные/дублированные declarations и функции в другом contract scope.
5. IMPORTANT: A/B evaluator должен учитывать INFRA_ERROR в знаменателях корректно
В core/ab_evaluator.py формулы:
valid_format_count = total_n - format_errors
compiled_count = total_n - format_errors - compilation_errors
могут засчитать INFRA_ERROR как валидный формат/скомпилированный кандидат.

Исправить политику знаменателей явно:
- Разделить число всех попыток, число evaluable candidates и число infrastructure failures.
- Для format/compile/replay rates указывать корректный denominator и число исключённых infra failures.
- INFRA_ERROR не считать успехом или неудачей модели.
- Добавить тесты с одним или несколькими INFRA_ERROR в baseline и LoRA наборах; проверить категории, знаменатели и итоговые проценты.
6. Evidence и обязательный формат отчёта
После исправлений:
1. Указать точный commit hash и подтвердить, что все файлы относятся к одной ревизии.
2. Приложить diff по всем изменённым файлам.
3. Для pytest привести точную команду, cwd, exit code, полную статистику passed/failed/errors/skipped/xfail и фактический stdout/stderr.
4. Привести реальные Foundry команды, имена тестов, stdout/stderr и exit code. Отдельно отметить, какие проверки выполнялись в Modal Sandbox, а какие локально или были mocked.
5. Привести end-to-end evidence для prompt и generated token IDs через production training path.
6. Привести orchestration-level evidence для replay exception handling.
7. Пересчитать A/B из raw records и показать знаменатели, исключения INFRA_ERROR и неопределённость.
8. Явно перечислить непроведённые проверки и причины.
9. Подтвердить, что GRPO не запускался, checkpoint-step-2 не менялся, новые checkpoints не создавались.
Важно: unit tests отдельных helper-функций не заменяют end-to-end/integration tests. Сообщение 65 passed, статус VERIFIED, наличие commit hash или ссылка на Modal run сами по себе не являются независимым доказательством. Не заявлять runtime verification без доступных логов и подтверждённой ревизии.
7. Acceptance gate Раунда 5
Раунд 5 не принят, пока независимо не подтверждены:
- правильная prompt identity на полном production path;
- сохранение и фактическое использование исходных generated token IDs на training path;
- корректная обработка replay infrastructure exceptions в orchestration;
- точная Solidity signature/interface validation;
- корректные A/B denominators при наличии INFRA_ERROR;
- реальные тестовые/Foundry доказательства для одной и той же source revision.
До отдельного письменного решения Супервизора:
TRAINING_STATUS = BLOCKED.
Сохранить checkpoint-step-2, все raw trajectories и audit records без изменений.
