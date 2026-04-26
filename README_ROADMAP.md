# ScanForge Roadmap

Дата обновления: 2026-04-27

Целевая платформа: только Linux. Основной runtime target - Ubuntu 22.04 LTS; Windows/WSL не считаются поддерживаемой средой запуска и используются здесь только для статических проверок или unit-тестов без Linux runtime.

Этот файл является рабочим планом доработок ScanForge. Его нужно обновлять после каждой выполненной задачи: менять метку статуса, добавлять краткую заметку о результате и фиксировать новые найденные пробелы.

## Метки

- `[DONE]` - выполнено и проверено тестами или smoke-проверкой.
- `[PARTIAL]` - базовая реализация есть, но до промышленного уровня еще нужны доработки.
- `[CODE-UNTESTED]` - код/скрипты уже изменены, но целевой Linux/e2e smoke не выполнялся; допустимы только статические проверки или unit-тесты без прямого запуска в Linux.
- `[TODO]` - запланировано, реализация не начата.
- `[BLOCKED]` - задача требует внешнего решения, доступа, лицензии, данных или уточнения.

## Текущее состояние

- `[DONE]` Веб-интерфейс запускается локально и через административный desktop launcher.
- `[DONE]` При административном запуске сервер слушает `0.0.0.0`, а браузер открывает локальный URL.
- `[DONE]` Свободный порт выбирается автоматически в диапазоне `8000-8100`.
- `[DONE]` Повторный запуск ярлыком переиспользует уже живой совместимый экземпляр.
- `[DONE]` Если сохраненный endpoint устарел или не отвечает, launcher стартует новый экземпляр.
- `[DONE]` Кнопки установки инструментов в настройках вызывают реальную установку deb-пакетов через системный пакетный менеджер.
- `[DONE]` После установки API возвращает обновленный inventory инструментов.
- `[DONE]` Ранее выполнены Linux-side проверки `./run-tests.sh`, `./scripts/run-web-smoke.sh`, `pip check`, `bash -n scripts/*.sh`; текущие изменения после отказа от WSL проверяются только Windows-side unit/static проверками и помечаются `[CODE-UNTESTED]` до smoke на Ubuntu 22.04.
- `[DONE]` Доступные Windows-side проверки от 2026-04-27 прошли: `py -m unittest discover -s tests` - 90 tests OK, 15 skipped из-за Linux-only runtime/broken WSL или отсутствующих dependency packages; `py_compile` для всех Python-файлов; `validate-matrix` для `tests/fixtures/ubuntu_2204_test_matrix.json`.
- `[BLOCKED]` Целевой Ubuntu 22.04 smoke/e2e и фактический validation report не выполнены в текущей среде; требуется реальный Ubuntu 22.04 host без WSL/Docker.
- `[BLOCKED]` `tests.test_portal_app` в текущем Windows Python не запускался из-за отсутствующего `fastapi`; это не подтверждает и не опровергает работу портала на целевой Ubuntu 22.04 среде.
- `[PARTIAL]` `[CODE-UNTESTED]` Без Linux runtime дополнительно реализованы audit log, production reverse-proxy/TLS документация и release checklist CLI для будущего Ubuntu 22.04 validation report; нужен целевой smoke/e2e на Ubuntu 22.04.

## Пункт 1. Базовая надежность и эксплуатационная готовность

- `[DONE]` Добавить Basic Auth/RBAC через переменные окружения.
- `[DONE]` Оставить публичными только health/runtime/static endpoints.
- `[DONE]` Запретить viewer-пользователю write-операции.
- `[DONE]` Добавить лимиты количества и размера upload-файлов.
- `[DONE]` Защитить выдачу артефактов от path traversal и доступа к незаявленным файлам.
- `[DONE]` Восстанавливать зависшие running-задачи после рестарта.
- `[DONE]` Добавить force-cancel для зависших задач.
- `[DONE]` Показывать runtime-логи в настройках и через API.
- `[DONE]` Усилить stop/start scripts: PID-файлы, process group stop, очистка stale endpoint.
- `[PARTIAL]` `[CODE-UNTESTED]` Включить безопасный режим по умолчанию для сетевого запуска: добавлен Basic Auth bootstrap для явно сетевого bind, генерация admin password в локальный auth bootstrap файл, чтение `admin_user` из bootstrap-файла и пропуск bootstrap-генерации при явно заданном `QA_PORTAL_ADMIN_PASSWORD`; нужен Linux smoke через launcher/systemd.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить audit log для входов, запусков анализов, установки пакетов, отмен задач и изменения настроек. Добавлен JSONL audit log `qa_portal/audit.py`, API `GET /api/audit`, санитаризация секретов, события auth/login, analysis start/rerun, tool install dry-run/queue, job cancel, settings update и finding review; исправлена выдача последних валидных JSONL-событий при битых строках в конце файла и покрыта unit-тестом; нужны Linux/web e2e и UI-экран просмотра/фильтрации audit events.
- `[PARTIAL]` `[CODE-UNTESTED]` Подготовить reverse-proxy/TLS инструкцию для production-развертывания. В `README.md` добавлена схема Ubuntu 22.04 deployment через loopback bind, Nginx TLS termination, `QA_PORTAL_ALLOWED_HOSTS` и Basic Auth env; нужна проверка на реальном Nginx/Ubuntu host.

## Пункт 2. Анализ уязвимостей уровня SAST/IAST

Цель: приблизить ScanForge к классу продукта, который анализирует код и выявляет уязвимости не хуже коммерческих SAST/IAST-решений уровня PT AI и АК ВС 3. Текущая реализация уже полезна, но пока это не полная замена промышленного анализатора.

### Уже сделано

- `[DONE]` Добавлены CWE/OWASP-ссылки к security findings.
- `[DONE]` Расширены языковые правила для Python, JavaScript/TypeScript, Go, shell, C/C++, Qt.
- `[DONE]` Добавлены проверки `eval`, `exec`, `shell=True`, unsafe YAML/pickle, Node VM, child_process, shell download pipe.
- `[DONE]` Добавлены проверки SQL-инъекций через строковую интерполяцию.
- `[DONE]` Добавлена проверка permissive CORS.
- `[DONE]` Добавлены Dockerfile-проверки: явный `USER root`/`USER 0` и отсутствие `USER` в финальной стадии.
- `[DONE]` Добавлен легкий taint-анализ: источники пользовательского ввода и sinks для shell, dynamic code execution и SQL.
- `[DONE]` Добавлены SARIF import/export: ScanForge импортирует внешние `.sarif`/`.sarif.json` results и генерирует `report.sarif`.
- `[DONE]` Добавлена базовая нормализация findings: severity, category, path, line, rule_id, confidence, references и fingerprint.
- `[DONE]` Тесты покрывают taint-flow findings, CWE/OWASP references и Dockerfile default root user.
- `[DONE]` Тесты покрывают SARIF import/export, появление `report.sarif` в артефактах pipeline и pause-safe порядок SARIF import.
- `[PARTIAL]` Есть dependency inventory, SBOM-подобные данные, локальная база уязвимостей и BDU/NVD enrichment.
- `[PARTIAL]` Есть dynamic/runtime контур: service runtime checks, replay artifacts, IAST hints, fuzzing plan и sanitizer-oriented dynamic analysis.

### Что еще нужно добавить в пункт 2

- `[PARTIAL]` `[CODE-UNTESTED]` Перейти от regex-only правил к parser-backed анализу: AST/CFG для Python, JS/TS, Go, C/C++ и shell. Добавлен первый parser-backed слой: Python AST для eval/exec/subprocess/sql/yaml/pickle и JS/TS syntax scanner для eval/Function/child_process/sql с внутрипроцедурным taint trace; нужны CFG, межфайловый анализ и полный e2e-прогон.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить межпроцедурный taint engine: перенос данных между функциями, методами, классами, файлами и модулями. Добавлен первый intra-file Python summary layer: taint переносится через функции, возвращающие source/tainted parameter, и через wrapper-функции, вызывающие sensitive sinks; локальное taint-состояние изолировано между несвязанными функциями; нужны методы/классы, межфайловый анализ и CFG.
- `[PARTIAL]` `[CODE-UNTESTED]` Ввести модели sources/sinks/sanitizers/validators для каждого языка и фреймворка. Добавлены Python-модели source/sink/sanitizer с import/alias resolution, сохранен JS/TS syntax слой; нужны расширенные модели для JS frameworks, Go, C/C++ и shell.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить sanitizer-aware подавление: не ругаться на данные после надежной валидации, escaping, prepared statements и allowlist-проверок. Python AST теперь подавляет taint с учетом sink-контекста: `shlex.quote` работает только для shell, HTML/URL/JSON escaping не гасит code/SQL sinks, `int`/`float` считаются универсальными sanitizer; нужны validator/allowlist-модели и prepared statement detection.
- `[PARTIAL]` Довести нормализацию findings до промышленного уровня: location range, typed evidence, full trace graph, remediation taxonomy, CWE, OWASP, CVSS-like severity.
- `[DONE]` Добавить импорт и экспорт SARIF, чтобы подключать внешние анализаторы и отдавать результаты в CI/CD.
- `[TODO]` Интегрировать внешние SAST-инструменты как optional engines: Bandit, Semgrep, ESLint security plugins, Gosec, Brakeman-compatible flow, cppcheck/clang-tidy SARIF.
- `[TODO]` Расширить C/C++ правила: use-after-free, double-free, integer overflow, format string, command injection, unsafe deserialization, path traversal, race conditions.
- `[TODO]` Расширить web/backend правила: SSRF, open redirect, auth bypass, insecure cookies, missing CSRF, weak JWT validation, IDOR, insecure file upload.
- `[TODO]` Расширить crypto rules: слабые алгоритмы, ECB, hardcoded keys, unsafe random, certificate validation bypass.
- `[TODO]` Сделать полноценный secrets scanner: entropy, known token formats, allowlist, baseline suppression.
- `[TODO]` Расширить dependency analysis до полноценного SCA: CycloneDX/SPDX export, OS packages, Docker layers, lockfile priority, CVE/BDU/CPE matching, reachability hints.
- `[TODO]` Добавить container/IaC scanning: Dockerfile, docker-compose, Kubernetes manifests, Helm, Terraform, Nginx/Apache configs.
- `[TODO]` Усилить DAST/IAST: OpenAPI import, crawler, auth session handling, request mutation, replay, proof artifacts, response evidence.
- `[TODO]` Довести fuzzing до реального запуска: сборка harness, corpus management, sanitizer build, crash triage, minimization, replay scripts.
- `[TODO]` Добавить профили соответствия: PT AI-like profile, АК ВС 3-like profile, CWE Top 25, OWASP ASVS, OWASP Top 10, FSTEC-oriented mapping.
- `[TODO]` Добавить triage workflow: false positive, accepted risk, fixed, retest required, expiration date, reviewer, comments.
- `[TODO]` Добавить baseline и diff по findings: новые, исправленные, повторные, изменившаяся severity, SLA.
- `[TODO]` Добавить quality gate policy builder: правила блокировки релиза по severity, confidence, CWE, компоненту и профилю соответствия.
- `[TODO]` Добавить benchmark corpus: набор намеренно уязвимых проектов и регрессионные тесты на каждое правило.

## Пункт 3. Установка, зависимости и инструменты

- `[DONE]` Bootstrap-скрипт устанавливает системные зависимости на apt-based системах.
- `[DONE]` Bootstrap создает `.venv`, ставит Python-зависимости и создает desktop shortcut.
- `[DONE]` Web UI показывает доступные инструменты и предлагает установку недостающих installable tools.
- `[DONE]` Install API поддерживает root, sudo с паролем из окружения, passwordless sudo и pkexec.
- `[PARTIAL]` `[CODE-UNTESTED]` Перевести долгие установки в background job с progress/log streaming, чтобы HTTP-запрос не ждал до 900 секунд. Добавлен JSON-backed install-job контур, API статусов, dry-run перед подтверждением, UI polling, восстановление stale queued/running jobs через list/status endpoints и корректные HTTP error-коды для неуспешного install API; нужен Linux smoke на отдельном Linux host.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить preflight для конфликтов apt sources и предупреждения о legacy keyring. Добавлен tool install preflight с privilege runner, duplicate apt sources и legacy keyring warnings; нужен прогон на реальном apt host.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить dry-run режим установки и подтверждение списка пакетов перед установкой. Добавлены `/api/tools/install/{tool}/dry-run`, browser confirmation, server-side package confirmation и отказ при устаревшем/несовпадающем списке пакетов; нужен e2e в Linux UI.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить поддержку dnf/pacman на уровне bootstrap, а не только на уровне inventory metadata. `setup-scanforge.sh` расширен под dnf/pacman; для текущего target Ubuntu 22.04 это не primary path, проверки нужны только если поддержка будет расширяться за пределы Ubuntu.

## Пункт 4. Запуск, ярлык и сетевой доступ

- `[DONE]` `run-server.sh` выбирает свободный порт и слушает все интерфейсы по умолчанию.
- `[DONE]` Desktop launcher открывает уже запущенный веб-интерфейс, если проект жив и совместим.
- `[DONE]` Desktop launcher стартует новый экземпляр, если проект еще не запущен.
- `[DONE]` Endpoint state хранится в `/var/run/scanforge/endpoint.env`.
- `[DONE]` Административные логи пишутся в `/var/log/scanforge`.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить UI-индикатор фактического сетевого адреса для доступа с других машин в LAN. Settings и `/api/system` показывают bind address, LAN URL и сетевые предупреждения; нужен smoke на реальном Linux host.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить явную настройку allowed hosts/CORS для сетевого режима. Добавлены `QA_PORTAL_ALLOWED_HOSTS`, `QA_PORTAL_CORS_ORIGINS`, `QA_PORTAL_CORS_ALLOW_CREDENTIALS`, middleware и документация; нужен e2e-прогон на Linux.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить systemd unit generator для стабильного сервисного запуска. Добавлен `scripts/generate-systemd-units.sh` для `scanforge-web.service`, `scanforge-worker.service` и env-файла; env-значения теперь quoted, service user по умолчанию берется из `SUDO_USER`/`USER`, добавлены auth bootstrap vars; нужна проверка установки на Linux host.
- `[PARTIAL]` `[CODE-UNTESTED]` Включить безопасную первичную настройку auth для сетевого запуска. Добавлен Basic Auth bootstrap для явно сетевого bind, генерация `data/settings/auth_bootstrap.json`, env-переменные `QA_PORTAL_AUTH_AUTO_SETUP`/`QA_PORTAL_AUTH_BOOTSTRAP`, CLI `python -m qa_portal.auth bootstrap`, чтение bootstrap `admin_user`, пропуск bootstrap при явном `QA_PORTAL_ADMIN_PASSWORD`, и `/api/runtime` больше не раскрывает сетевые детали; нужен Linux smoke через launcher/systemd.

## Пункт 5. Интерфейс и пользовательские сценарии

- `[DONE]` Settings page показывает toolchain, environment diagnostics, runtime logs и AI backend.
- `[DONE]` Асинхронные формы показывают состояние `Installing...`, `Applying...`, `Done.` или ошибку.
- `[TODO]` Добавить страницу управления правилами: включение/отключение правил, severity override, suppression policy.
- `[TODO]` Добавить страницу triage findings с фильтрами по CWE, severity, source, confidence, статусу и владельцу.
- `[TODO]` Добавить сравнение двух запусков в UI: новые/исправленные/оставшиеся проблемы.
- `[PARTIAL]` Добавить machine-readable exports: SARIF уже готов, далее нужны CycloneDX, SPDX и расширенный JSON profile.

## Пункт 6. Тестирование и контроль качества

- `[DONE]` Unit tests покрывают анализаторы, портал, tool installer, desktop launcher, AI review и runtime scans.
- `[DONE]` Shell tests покрывают базовые scripts.
- `[DONE]` Ранее web smoke проверял dashboard, settings, RU localization, создание job, worker и HTML report; новые изменения после отказа от WSL требуют повторного smoke на Ubuntu 22.04.
- `[DONE]` Windows-side test harness приведен к текущей реальности: Linux-only shell/portal/worker тесты теперь корректно пропускаются без WSL, dependency-тесты reporting пропускаются при отсутствии `fpdf2`, а HTTP test servers закрываются через `shutdown` перед `server_close`.
- `[DONE]` SARIF normalization покрывает Windows absolute paths и приводит findings к относительным путям проекта.
- `[TODO]` Добавить Playwright/e2e проверки для install buttons, settings refresh, job triage и report downloads.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить тестовую матрицу для Ubuntu 22.04, root/non-root, pkexec/sudo/no sudo. Добавлен machine-readable matrix file `tests/fixtures/ubuntu_2204_test_matrix.json`, unit-валидатор `tests/test_ubuntu_2204_matrix.py` и общий валидатор `qa_portal/ubuntu_validation.py`; исправлен sudo-password marker на `SCANFORGE_SUDO_PASSWORD`; прямой прогон на Ubuntu 22.04 не выполнялся.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить regression fixtures для каждого security rule. Добавлен первый JSON corpus `tests/fixtures/security_regression_cases.json` и unit-тест `tests/test_security_regression_fixtures.py` для Python/JS/Go/shell/C++/Docker/security references; нужны fixtures для будущих правил, негативные FP-кейсы и e2e-прогон на Ubuntu 22.04.
- `[TODO]` Добавить performance benchmark на больших репозиториях и архивах.

## Пункт 7. Ubuntu 22.04 release validation

- `[PARTIAL]` `[CODE-UNTESTED]` Зафиксировать целевую test matrix для Ubuntu 22.04 LTS: root, non-root with passwordless sudo, non-root with sudo password, pkexec и no-privilege/preflight-block сценарии описаны в `tests/fixtures/ubuntu_2204_test_matrix.json`; структура, запрет WSL/Docker-команд, запрет bare `python` и корректный `SCANFORGE_SUDO_PASSWORD` покрыты `tests/test_ubuntu_2204_matrix.py` и `qa_portal/ubuntu_validation.py`.
- `[PARTIAL]` `[CODE-UNTESTED]` Подготовить выполнение матрицы на реальном Ubuntu 22.04 host без WSL/Docker: добавлен runner `python3 -m qa_portal.ubuntu_validation run-matrix`, который блокирует запуск на нецелевой ОС, поддерживает фильтр сценариев, stop-on-failure, timeouts, логи и JSON report; фактический прогон команд на Ubuntu 22.04 еще не выполнялся.
- `[PARTIAL]` `[CODE-UNTESTED]` Добавить machine-readable отчет о фактическом прогоне матрицы: начат пункт 8 с JSON-шаблоном отчета, host facts, summary counts, scenario/check statuses, log/artifact fields и CLI-валидацией; фактический Ubuntu-прогон еще не выполнялся.

## Пункт 8. Machine-readable Ubuntu validation reports

- `[PARTIAL]` `[CODE-UNTESTED]` Добавить формат и валидатор отчета Ubuntu 22.04 validation: реализован `qa_portal/ubuntu_validation.py` с командами `validate-matrix`, `write-report-template`, `validate-report` и `run-matrix`; unit-тесты `tests/test_ubuntu_validation.py` проверяют template coverage, summary counts, status/exit_code/log invariants, отсутствие неизвестных сценариев и ошибку с неверным sudo env marker.
- `[PARTIAL]` `[CODE-UNTESTED]` Связать report validator с runner: report schema принимает статусы `passed`/`failed`/`skipped`/`blocked`, exit code, duration, log path и artifacts; прямой запуск команд матрицы на Ubuntu 22.04 и фактический completed report еще отсутствуют.
- `[PARTIAL]` `[CODE-UNTESTED]` Сохранить результаты фактического Ubuntu 22.04 прогона в `data/validation/ubuntu_2204_validation_report.json` и добавить проверку этого файла в release checklist. Добавлена CLI-команда `python3 -m qa_portal.ubuntu_validation check-release`, которая требует completed report без failed/blocked/skipped/not-run checks; фактический Ubuntu 22.04 report еще отсутствует.

## Пункт 9. Ubuntu 22.04 validation runner

- `[PARTIAL]` `[CODE-UNTESTED]` Реализовать runner для matrix checks: `qa_portal/ubuntu_validation.py` теперь запускает команды из `tests/fixtures/ubuntu_2204_test_matrix.json`, пишет логи в `data/validation/logs`, собирает `data/validation/ubuntu_2204_validation_report.json`, валидирует completed report, блокирует выполнение на не-Ubuntu 22.04 host и не запускает WSL/Docker.
- `[PARTIAL]` `[CODE-UNTESTED]` Проверить runner unit-тестами без Linux runtime: `tests/test_ubuntu_validation.py` покрывает non-target blocking без запуска команд, выполнение выбранного сценария через fake runner, summary counts, log paths, неизвестный `--scenario`, status/exit_code invariants и `require_completed`.
- `[TODO]` Выполнить `python3 -m qa_portal.ubuntu_validation run-matrix` на реальном Ubuntu 22.04 host и приложить фактические логи setup/tests/web-smoke/tool-install/systemd.

## Следующие рекомендуемые шаги

1. `[BLOCKED]` Выполнить `python3 -m qa_portal.ubuntu_validation run-matrix` на реальном Ubuntu 22.04 host, сохранить `data/validation/ubuntu_2204_validation_report.json`, проверить `check-release` и приложить логи setup/tests/web-smoke/tool-install/systemd. В текущей Windows-среде без WSL/Docker этот пункт выполнить нельзя.
2. `[BLOCKED]` После успешного Ubuntu 22.04 прогона снять `[CODE-UNTESTED]` с подтвержденных пунктов: auth bootstrap, network mode, systemd unit generator, tool install background jobs, dry-run/package confirmation и validation runner.
3. `[PARTIAL]` `[CODE-UNTESTED]` Довести audit log до product-ready уровня: добавить UI-экран фильтрации audit events, экспорт JSONL/JSON, retention/rotation policy и e2e-проверки auth/job/tool/settings событий.
4. `[PARTIAL]` `[CODE-UNTESTED]` Проверить reverse-proxy/TLS инструкцию на Ubuntu 22.04 с Nginx, systemd и Basic Auth bootstrap; после проверки перевести пункт в `[DONE]`.
5. `[TODO]` Добавить Playwright/e2e проверки для install buttons, settings refresh, job triage, report downloads, audit API и release validation report status.
6. `[TODO]` Реализовать UI rule management: включение/отключение правил, severity override, suppression policy и audit events для изменений правил.
7. `[TODO]` Реализовать triage UI для findings: фильтры по CWE/severity/source/confidence/status/owner, bulk update, expiration для accepted risk и export.
8. `[TODO]` Добавить baseline/diff UI и API: новые, исправленные, повторные findings, изменение severity, SLA и сравнение двух запусков.
9. `[TODO]` Расширить parser-backed SAST: Python CFG и межфайловый taint, затем JS framework models, Go/C/C++ модели и regression fixtures на каждое новое правило.
10. `[TODO]` Интегрировать optional external SAST engines через SARIF: Bandit, Semgrep, ESLint security, Gosec, cppcheck/clang-tidy.
11. `[TODO]` Добавить полноценные exports: CycloneDX, SPDX и расширенный ScanForge JSON profile.
12. `[TODO]` Реализовать secrets scanner, SCA reachability/CPE matching, IaC/container scanning, DAST/IAST crawler, fuzzing harness и benchmark corpus.
