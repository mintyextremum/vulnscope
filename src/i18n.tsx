import { createContext, useContext } from "react";

/**
 * Localization.
 *
 * gettext-style: the Russian source string is its own key, and `EN` maps it to
 * English. This keeps the JSX readable (the Russian text stays in place) and
 * avoids inventing a key for every one of a few hundred strings — a missing
 * translation falls back to the source rather than showing a bare key.
 *
 * Interpolation uses `{name}` placeholders so a value can sit anywhere in the
 * sentence, since word order differs between languages.
 *
 * Scope: this covers the application shell — navigation, settings, the scan
 * screens, tooltips, empty states. The built-in security rule catalogue (titles
 * and descriptions of the 114 rules, emitted by the Rust engine) is separate
 * content and stays in its source language for now.
 */
export type Lang = "ru" | "en";

export const LangContext = createContext<Lang>("ru");

/** Fills `{name}` placeholders. */
function interpolate(s: string, vars?: Record<string, string | number>): string {
  if (!vars) return s;
  let out = s;
  for (const [k, v] of Object.entries(vars)) out = out.split(`{${k}}`).join(String(v));
  return out;
}

export function translate(
  lang: Lang,
  source: string,
  vars?: Record<string, string | number>
): string {
  const base = lang === "en" ? EN[source] ?? source : source;
  return interpolate(base, vars);
}

/** Hook form: `const t = useT(); t("Начать сканирование")`. */
export function useT() {
  const lang = useContext(LangContext);
  return (source: string, vars?: Record<string, string | number>) =>
    translate(lang, source, vars);
}

/** For code outside React (helpers that already receive the language). */
export type TFn = (source: string, vars?: Record<string, string | number>) => string;

// ---------------------------------------------------------------- dictionary

/**
 * English for every shell string. A key absent here renders as the Russian
 * source, which is the intended fallback while a translation is missing.
 */
export const EN: Record<string, string> = {
  // -- titlebar & top-level nav
  Настройки: "Settings",
  Правила: "Rules",
  Свои: "Custom",
  Экспорт: "Export",
  "Новое сканирование": "New scan",
  Свернуть: "Minimize",
  Развернуть: "Maximize",
  "Свернуть в окно": "Restore",
  Закрыть: "Close",
  Назад: "Back",
  Отмена: "Cancel",
  Отменить: "Cancel",
  "Сбросить всё": "Reset all",

  // -- setup screen
  "Проверьте код на уязвимости": "Check your code for vulnerabilities",
  "Локальный анализ без отправки кода наружу. Находит опасные конструкции, секреты в исходниках и известные CVE в зависимостях.":
    "Local analysis, nothing leaves your machine. Finds dangerous constructs, secrets in source, and known CVEs in dependencies.",
  "Локальная папка": "Local folder",
  Репозиторий: "Repository",
  Выбрать: "Browse",
  "D:\\Projects\\my-app": "D:\\Projects\\my-app",
  "https://github.com/owner/repo": "https://github.com/owner/repo",
  "Файлы читаются только на этом компьютере и никуда не отправляются.":
    "Files are read on this computer only and never uploaded.",
  "Что проверять": "What to check",
  "Секреты в коде": "Secrets in code",
  "Ключи API, токены, пароли, приватные ключи": "API keys, tokens, passwords, private keys",
  "CVE в зависимостях": "CVEs in dependencies",
  "Запрос к базе OSV.dev, результат кэшируется": "Queries OSV.dev, result is cached",
  "Учитывать .gitignore": "Respect .gitignore",
  "Пропускать то, что не попадает в репозиторий": "Skip what the repo ignores",
  "Включая зависимости": "Include dependencies",
  "Сканировать node_modules, venv и т.п. Заметно дольше":
    "Scan node_modules, venv, etc. Noticeably slower",
  "Начать сканирование": "Start scan",
  "Укажите папку с проектом": "Choose a project folder",
  "Вставьте ссылку на репозиторий": "Paste a repository URL",

  // -- external scanners card
  "Внешние сканеры": "External scanners",
  "Проверить снова": "Re-check",
  "Включить все": "Enable all",
  "Выучить все": "Disable all",
  "Выключить все": "Disable all",
  "проверяем…": "checking…",
  "Спрашиваем у каждого сканера его версию — это запуск процесса на каждый, пара секунд.":
    "Asking each scanner for its version — a process launch each, a couple of seconds.",
  "{n} из {total} сканеров участвуют в сканировании":
    "{n} of {total} scanners will run",
  "{n} установлено, но выключено": "{n} installed but off",
  "Приложение работает и без них — это покрытие поверх {n} встроенных правил. Установка идёт через ваш пакетный менеджер, который сам проверяет подлинность пакета: скачивать бинарники напрямую сканер безопасности не должен.":
    "The app works without them — this is coverage on top of {n} built-in rules. Installation goes through your own package manager, which verifies what it fetches: a security scanner should not download binaries directly.",
  "не установлен": "not installed",
  "не подключён": "not wired up",
  "Использовать при сканировании": "Use during scan",
  "Сначала установите": "Install first",
  "Пока не подключён к сканированию": "Not wired into scanning yet",
  "Установить можно, но его вывод пока не разбирается":
    "Can be installed, but its output is not parsed yet",
  Установить: "Install",
  "Ставится…": "Installing…",
  "Ни один из подходящих пакетных менеджеров не найден. Установите вручную:":
    "No suitable package manager found. Install manually:",
  "Команда выполнится как есть, без шелла. Проверить её можно прямо здесь.":
    "The command runs as-is, no shell. You can review it right here.",
  Скопировать: "Copy",
  Выполнить: "Run",
  Установлено: "Installed",
  "Не удалось": "Failed",
  "Официальная страница проекта": "Project home page",
  "Ещё {n} сканера": "{n} more scanners",
  "установка есть, разбор вывода — нет": "installable, output not parsed",
  Скрыть: "Hide",

  // -- scan scopes/labels (tool scope strings from backend)
  "Много языков": "Many languages",
  Python: "Python",
  Rust: "Rust",
  Go: "Go",
  JavaScript: "JavaScript",
  Секреты: "Secrets",
  Зависимости: "Dependencies",
  Инфраструктура: "Infrastructure",

  // -- scanning screen (phase labels)
  Подготовка: "Preparing",
  "Клонирование репозитория": "Cloning repository",
  Клонирование: "Cloning",
  "Поиск файлов": "Discovering files",
  "Анализ кода": "Analyzing code",
  "Разбор зависимостей": "Resolving dependencies",
  Зависимости_phase: "Dependencies",
  "Запрос базы CVE (OSV.dev)": "Querying CVE database (OSV.dev)",
  "База CVE": "CVE database",
  "Внешние сканеры_phase": "External scanners",
  "Формирование отчёта": "Building report",
  Отчёт: "Report",
  Готово: "Done",
  Отменено: "Cancelled",
  Ошибка: "Error",
  Файлов: "Files",
  Находок: "Findings",
  "Файлов/с": "Files/s",
  Осталось: "Remaining",
  Прошло: "Elapsed",
  "идёт работа": "working",

  // -- result tabs & overview
  Обзор: "Overview",
  Находки: "Findings",
  Код: "Code",
  Пропущено: "Skipped",
  "Всего находок": "Total findings",
  "Файлов проверено": "Files scanned",
  "Строк кода": "Lines of code",
  "Зависимостей проверено": "Dependencies checked",
  "Время сканирования": "Scan time",
  "Объём кода": "Code size",
  "По уровню опасности": "By severity",
  Языки: "Languages",
  "Файлы не найдены": "No files found",
  "Использованные движки": "Engines used",
  "Встроенные правила": "Built-in rules",
  "Свои правила ({n})": "Custom rules ({n})",
  "Исправлено с прошлого скана": "Fixed since last scan",
  "и ещё {n}": "and {n} more",
  новых: "new",
  исправлено: "fixed",
  "без изменений": "unchanged",
  "с прошлого скана {date}": "since last scan {date}",
  "Первое сканирование этой цели — сравнивать пока не с чем. Следующий прогон покажет, что изменилось.":
    "First scan of this target — nothing to compare yet. The next run will show what changed.",
  "Подавлено находок: {n}. Они исключены из счётчиков и скрыты — включите «Подавленные» над списком, чтобы посмотреть или вернуть. Правила лежат в":
    "Suppressed findings: {n}. They are excluded from the counts and hidden — turn on “Suppressed” above the list to view or restore them. The entries live in",
  "Сканирование отменено — результаты неполные. Отсутствие находок здесь не означает, что код чист: большая часть файлов не проверялась.":
    "Scan cancelled — results are incomplete. No findings here does not mean the code is clean: most files were not checked.",
  "Проверка не завершена": "Scan not finished",

  // -- findings list & filters
  "Поиск: название, путь, категория, CWE, CVE, код": "Search: title, path, category, CWE, CVE, code",
  "показать находки во всех файлах": "show findings from every file",
  "Пересканировать": "Re-scan",
  "Показать файл в проводнике": "Reveal the file in the file manager",
  "Экспорт отфильтрованного в Markdown": "Export filtered to Markdown",
  "Экспорт отфильтрованного в CSV": "Export filtered to CSV",
  "Экспорт отфильтрованного в HTML": "Export filtered to HTML",
  "{n} из {total} находок": "{n} of {total} findings",
  "Отфильтрованная выборка: {n} из {total} находок полного отчёта.":
    "A filtered selection: {n} of {total} findings from the full report.",
  // Keybind actions and their groups: backend strings rendered on the settings
  // screen, which used to print them raw and so stayed Russian in English.
  "Командная палитра": "Command palette",
  "Экспорт отчёта": "Export report",
  "Вкладка «Обзор»": "Overview tab",
  "Вкладка «Находки»": "Findings tab",
  "Вкладка «Код»": "Code tab",
  "Вкладка «Пропущено»": "Skipped tab",
  "Следующая находка": "Next finding",
  "Предыдущая находка": "Previous finding",
  "Открыть находку в коде": "Open the finding in code",
  "Поиск по файлам": "Search files",
  "Навигация": "Navigation",
  "Вкладки": "Tabs",
  "Копировать": "Copy",
  "Скопировано": "Copied",
  "Скопировать находку как Markdown — для тикета или чата": "Copy the finding as Markdown — for a ticket or chat",
  Очистить: "Clear",
  "Только новые": "New only",
  Подавленные: "Suppressed",
  "скрыто {n}": "{n} hidden",
  "Сбросить фильтры": "Reset filters",
  "Под фильтры ничего не подошло": "Nothing matches the filters",
  "Здесь ничего не найдено": "Nothing found here",
  новое: "new",
  подавлено: "suppressed",
  "Только с находками": "With findings only",
  "Поиск по пути…": "Search by path…",
  Файлы: "Files",

  // -- finding detail (CSS uppercases these; the source text is mixed case)
  Подавить: "Suppress",
  Вернуть: "Restore",
  "В чём проблема": "The problem",
  "Как исправить": "How to fix",
  Классификация: "Classification",
  Правило: "Rule",
  Источник: "Source",
  Категория: "Category",
  Достоверность: "Confidence",
  Ссылки: "References",
  Пакет: "Package",
  "Исправлено в": "Fixed in",
  "Не было в предыдущем сканировании": "Was not in the previous scan",
  "Выберите находку, чтобы увидеть детали": "Select a finding to see details",
  "Выберите файл слева": "Select a file on the left",
  "Загрузка файла…": "Loading file…",
  "{n} отмечено": "{n} flagged",
  "Git не найден в PATH — сканирование по ссылке недоступно.":
    "Git not found in PATH — scanning by URL is unavailable.",
  "Команды — Ctrl+K": "Commands — Ctrl+K",
  Команды: "Commands",
  "Запись попадёт в": "The entry goes into",
  "в проекте — она версионируется вместе с кодом и видна на ревью.":
    "in the project — it is versioned with the code and visible in review.",
  "Причина: почему это не проблема": "Reason: why this is not a problem",
  "Все находки этого правила в файле": "All findings of this rule in the file",
  "А не только эту одну": "Not just this one",
  "Укажите причину — без неё подавление невозможно отличить от сокрытия проблемы":
    "State a reason — without it, suppression is indistinguishable from hiding a problem",
  "Подавлено: {reason}": "Suppressed: {reason}",

  // -- severity & confidence
  Критическая: "Critical",
  Высокая: "High",
  Средняя: "Medium",
  Низкая: "Low",
  Информация: "Info",
  "Высокая точность": "High confidence",
  "Средняя точность": "Medium confidence",
  "Низкая точность": "Low confidence",

  // -- skipped tab
  "Пропущенные файлы": "Skipped files",

  // -- rules catalogue screen (chrome only)
  "Каталог правил": "Rule catalogue",
  "Поиск по правилам…": "Search rules…",
  "Ничего не найдено": "Nothing found",
  Всего: "Total",

  // -- custom rules editor (chrome)
  "Свои правила": "Custom rules",
  "Создать правило": "New rule",
  "Создать первое правило": "Create your first rule",
  Сохранить: "Save",
  Удалить: "Delete",
  Проверить: "Test",

  // -- settings tabs
  Сканирование: "Scanning",
  Клавиши: "Keys",
  Вид: "Appearance",
  Доступность: "Accessibility",

  // -- settings: appearance
  Схема: "Scheme",
  "Акцентный цвет": "Accent color",
  Плотность: "Density",
  Просторно: "Comfortable",
  Плотно: "Compact",
  "изменено: {n}": "changed: {n}",
  "Из этих значений собран весь интерфейс, включая подсветку кода. Правки применяются сразу и хранятся в":
    "The whole interface is built from these values, syntax highlighting included. Edits apply at once and are stored in",
  "Показать все цвета": "Show all colors",
  Свернуть_look: "Collapse",
  Импорт: "Import",
  "Сбросить к схеме": "Reset to scheme",
  "Подсветка синтаксиса до": "Highlight syntax up to",
  строк: "lines",
  "Файл настроек:": "Settings file:",
  "тему можно править и прямо в нём, ключ": "the theme can be edited there too, key",

  // -- settings: accessibility
  "Масштаб интерфейса": "Interface scale",
  "Увеличивает весь интерфейс, а не только шрифт, поэтому на 200% ничего не наезжает (WCAG 1.4.4).":
    "Scales the whole interface, not just the font, so nothing overlaps at 200% (WCAG 1.4.4).",
  Меньше: "Smaller",
  Больше: "Larger",
  Сброс: "Reset",
  "Уменьшить анимацию": "Reduce motion",
  "Отключает переходы и фоновое движение. Системная настройка учитывается и без этого.":
    "Turns off transitions and background motion. The OS setting is honoured regardless.",
  "Не показывать фоновое свечение": "Hide the background glow",
  "Убирает плавно движущиеся пятна за интерфейсом.":
    "Removes the slowly drifting lights behind the interface.",
  "Всегда показывать фокус": "Always show focus",
  "Рамка фокуса видна и после клика мышью, не только при навигации с клавиатуры.":
    "The focus ring is shown after a mouse click too, not only during keyboard navigation.",
  "Подписывать уровень опасности": "Label the severity",
  "Добавляет слово («Крит», «Выс»…) рядом со счётчиками — на случай, когда цвета трудно различить (WCAG 1.4.1).":
    "Adds a word (“Crit”, “High”…) next to the counts — for when colours are hard to tell apart (WCAG 1.4.1).",
  "Подчёркивать ссылки": "Underline links",
  "Ссылки отличаются не только цветом.": "Links are distinguished by more than colour.",
  "Крупные области нажатия": "Large hit areas",
  "Кнопки и переключатели не меньше 24×24 px (WCAG 2.5.8).":
    "Buttons and switches at least 24×24 px (WCAG 2.5.8).",
  "Смысловые цвета (уровни опасности) проверены на контраст WCAG 2.2 AA и на три типа дальтонизма во всех схемах. У каждого уровня есть свой значок, так что цвет никогда не единственный признак.":
    "The semantic colours (severity levels) are checked for WCAG 2.2 AA contrast and for three types of colour blindness in every scheme. Each level has its own icon, so colour is never the only cue.",

  // -- command palette
  "Команда или действие…": "Command or action…",
  "Каталог правил (встроенные)": "Rule catalogue (built-in)",

  // -- settings: scanning tab
  "Максимальный размер файла": "Maximum file size",
  МБ: "MB",
  "Файлы крупнее пропускаются: это почти всегда сгенерированные данные, а не код.":
    "Larger files are skipped: they are almost always generated data, not code.",
  "Длина строки для «минифицирован»": "Line length for “minified”",
  символов: "chars",
  "Файл со строкой длиннее считается бандлом и не сканируется.":
    "A file with a longer line is treated as a bundle and not scanned.",
  "Находок на файл": "Findings per file",
  "макс.": "max",
  "Предел, чтобы одно шумное правило не залило собой отчёт.":
    "A cap so one noisy rule cannot flood the report.",
  "Кэш OSV": "OSV cache",
  дней: "days",
  "Сколько ответы OSV считаются свежими. 0 — всегда спрашивать заново.":
    "How long OSV answers stay fresh. 0 means always re-query.",
  "Параллельных запросов к OSV": "Concurrent OSV requests",
  "Больше — быстрее, но вежливее к бесплатному API держать умеренно.":
    "More is faster, but keep it modest to be kind to the free API.",
  "Поведение правил": "Rule behaviour",
  "Пропускать шумные правила в тестах": "Skip noisy rules in tests",
  "Math.random и подобные в тестовых файлах — не проблема.":
    "Math.random and the like in test files are not a problem.",
  "Игнорировать комментарии": "Ignore comments",
  "Закомментированный код не считается уязвимостью.":
    "Commented-out code is not treated as a vulnerability.",
  "Что включено по умолчанию": "Enabled by default",
  "Включая зависимости (node_modules и т.п.)": "Include dependencies (node_modules, etc.)",
  "Настройки сброшены": "Settings reset",
  "Загрузка настроек…": "Loading settings…",

  // -- settings: keys tab
  "Нажмите на сочетание и введите новое. Backspace — очистить, Esc — отмена.":
    "Click a shortcut and press a new one. Backspace clears, Esc cancels.",
  "Одно сочетание назначено на несколько действий — сработает только одно.":
    "One shortcut is bound to several actions — only one will fire.",
  "Конфликт сочетаний": "Shortcut conflict",
  конфликт: "conflict",
  "Нажмите клавиши…": "Press keys…",

  // -- settings: appearance leftovers
  "Акцент {c}": "Accent {c}",
  "Свернуть цвета": "Collapse",
  "Значение с прозрачностью — правится текстом": "Value with transparency — edit as text",
  "Вернуть к схеме": "Reset to scheme",
  "Масштаб интерфейса, проценты": "Interface scale, percent",
  "На файлах длиннее подсветка отключается: она работает в главном потоке и на бандлах ощутимо тормозит.":
    "Highlighting is turned off past this: it runs on the main thread and drags on bundles.",

  // -- scan summary (spoken)
  "Сканирование отменено, результаты неполные. Отсутствие находок не означает, что код чист.":
    "Scan cancelled, results are incomplete. No findings does not mean the code is clean.",
  "Сканирование завершено. Находок нет. Проверено файлов: {files}.":
    "Scan complete. No findings. Files scanned: {files}.",
  "Сканирование завершено. Найдено {total}: {breakdown}.":
    "Scan complete. Found {total}: {breakdown}.",
  "С прошлого скана: {new} новых, {fixed} исправлено.":
    "Since last scan: {new} new, {fixed} fixed.",
  "Подавлено: {n}.": "Suppressed: {n}.",

  // -- progress live region
  "{label}: {pct}%, проверено {done} из {total}":
    "{label}: {pct}%, checked {done} of {total}",
  "Вкладка: {name}": "Tab: {name}",

  // -- misc counts
  "{n} файлов": "{n} files",
  "{n} строк": "{n} lines",

  // -- command palette entries
  "сначала укажите цель": "choose a target first",
  "Выбрать папку…": "Browse for a folder…",
  "обзор диска": "browse the disk",
  "Сканировать локальную папку": "Scan a local folder",
  "Сканировать репозиторий": "Scan a repository",
  встроенные: "built-in",
  "лимиты, клавиши, вид": "limits, keys, appearance",
  "создать и изменить": "create and edit",
  "Экспорт отчёта в JSON": "Export report to JSON",
  "Отменить сканирование": "Cancel scan",
  "Экспорт в SARIF (для CI)": "Export to SARIF (for CI)",
  "GitHub code scanning и др.": "GitHub code scanning and more",
  "Экспорт в Markdown": "Export to Markdown",
  "для PR, issue или чата": "for a PR, issue, or chat",
  "Отчёт VulnScope": "VulnScope report",
  "Сканирование отменено — результаты неполные.": "Scan cancelled — results are incomplete.",
  "Найдено: {total} · файлов: {files} · строк: {lines}": "Found: {total} · files: {files} · lines: {lines}",
  "Сводка": "Summary",
  "Уровень": "Severity",
  "Количество": "Count",
  "правило": "rule",
  "Находка": "Finding",
  "Сгенерировано VulnScope": "Generated by VulnScope",
  "Файл": "File",
  "Причина": "Reason",
  "Строка": "Line",
  "Подавлено": "Suppressed",
  "Да": "Yes",
  "Нет": "No",
  "Экспорт в CSV (для таблиц)": "Export to CSV (for spreadsheets)",
  "для сортировки и триажа": "for sorting and triage",
  "Экспорт в HTML (для браузера)": "Export to HTML (for a browser)",
  "открыть или напечатать в PDF": "open it or print to PDF",
  "Скопировать отчёт (Markdown)": "Copy report (Markdown)",
  "в буфер обмена — для PR или чата": "to the clipboard — for a PR or chat",
  "Отчёт скопирован в буфер обмена": "Report copied to the clipboard",
  "Не удалось скопировать — используйте экспорт в Markdown": "Couldn't copy — use Export to Markdown",
  "Находок нет": "No findings",
  "Показать только новые": "Show new only",
  "Показать все находки": "Show all findings",

  // -- empty states
  "Нет файлов с находками": "No files with findings",

  // -- misc ternary literals
  "Публичный репозиторий клонируется во временную папку. Она нужна, чтобы показывать код после проверки, и очищается при следующем сканировании.":
    "A public repository is cloned into a temp folder. It is needed to show the code after the scan and is cleared on the next run.",
  "нет исправления": "no fix",
  "Прогресс сканирования": "Scan progress",

  // -- settings: theme tokens leftovers
  "Токены темы": "Theme tokens",
  "Тема VulnScope": "VulnScope theme",
  Тема: "Theme",
  "Пропущено записей, не похожих на цвет: {n}": "Skipped entries that are not colours: {n}",
  "Не удалось прочитать тему: {e}": "Could not read the theme: {e}",
  "{on} включено, {installed} установлено, {missing} не установлено":
    "{on} enabled, {installed} installed, {missing} not installed",

  // -- rules catalogue
  "Поиск по id, названию, CWE, OWASP…": "Search by id, title, CWE, OWASP…",
  Все: "All",
  "Загрузка правил…": "Loading rules…",
  "Требует проверки": "Needs review",

  // -- skipped view
  "Эти файлы не анализировались. Бинарники, медиа и архивы не содержат читаемого исходного кода, поэтому проверить их статическим анализом невозможно.":
    "These files were not analysed. Binaries, media and archives hold no readable source, so static analysis cannot check them.",
  "Все найденные файлы были проверены": "All discovered files were checked",
  "…и ещё {n}": "…and {n} more",

  // -- custom rule editor
  "Своё правило": "Custom rule",
  "Правило создано": "Rule created",
  "Правило сохранено": "Rule saved",
  "Правило удалено": "Rule deleted",
  "Набор правил выгружен": "Rule set exported",
  "Импортировано правил: {n}": "Rules imported: {n}",
  "Загрузка…": "Loading…",
  "Своих правил пока нет": "No custom rules yet",
  "Правило — это регулярное выражение плюс описание и рекомендация. Оно работает наравне со встроенными: так же пропускает комментарии и тестовые файлы.":
    "A rule is a regular expression plus a description and a recommendation. It works like the built-in ones: it skips comments and test files too.",
  "Файл правил:": "Rules file:",
  Выключить: "Disable",
  Включить: "Enable",
  "все языки": "all languages",
  Идентификатор: "Identifier",
  "Например MY-001. Префикс VS- занят встроенными правилами.":
    "e.g. MY-001. The VS- prefix is reserved for built-in rules.",
  Название: "Title",
  "Что нашли — коротко": "What was found, briefly",
  "Регулярное выражение": "Regular expression",
  "Синтаксис Rust regex: без lookahead и обратных ссылок.":
    "Rust regex syntax: no lookahead or backreferences.",
  Важность: "Severity",
  "Ничего не выбрано — правило работает во всех текстовых файлах.":
    "Nothing selected — the rule runs on all text files.",
  "Почему это опасно и что может сделать атакующий":
    "Why it is dangerous and what an attacker could do",
  "Конкретное действие, а не «будьте осторожны»":
    "A concrete action, not “be careful”",
  "Не срабатывать, если строка содержит": "Do not fire if the line contains",
  "Через запятую": "Comma-separated",
  "Не срабатывать в тестах": "Do not fire in tests",
  "Включите, если правило шумит на тестовых файлах":
    "Enable if the rule is noisy on test files",
  "Проверка на примере": "Test on a sample",
  "Вставьте сюда код, чтобы увидеть,\nчто правило поймает":
    "Paste code here to see what the rule catches",
  "Введите выражение и пример кода": "Enter an expression and a sample",
  "Сработает на строках: {lines}": "Would fire on lines: {lines}",
  "На этом примере не срабатывает": "Does not fire on this sample",
  "Отсечено правилом «не срабатывать, если содержит»":
    "Filtered by the “do not fire if contains” rule",
  отсечено: "filtered",

  // -- backend content: rule catalogue, secrets, categories, labels
  // Go/Java/PHP rules added 16.07.2026
  "Слабый шифр (DES/RC4)": "Weak cipher (DES/RC4)",
  "DES с 56-битным ключом перебирается, а поток RC4 имеет статистические смещения. Оба алгоритма считаются сломанными.":
    "DES has a 56-bit key that can be brute-forced, and the RC4 stream has statistical biases. Both algorithms are considered broken.",
  "Используйте AES-GCM через crypto/aes и crypto/cipher со случайным nonce на каждое сообщение.":
    "Use AES-GCM via crypto/aes and crypto/cipher with a fresh nonce per message.",
  "Приведение к template.HTML отключает экранирование": "Casting to template.HTML disables escaping",
  "Значения типов template.HTML/JS/URL вставляются в шаблон без автоэкранирования. Если в них попадает пользовательский ввод, это XSS.":
    "Values of type template.HTML/JS/URL are inserted into the template without auto-escaping. If user input reaches them, it is XSS.",
  "Не приводите пользовательские данные к template.HTML. Пусть html/template экранирует их сам, передавая как обычную строку.":
    "Do not cast user data to template.HTML. Pass it as a plain string and let html/template escape it.",
  "Файл создаётся с правами 0777": "File created with 0777 permissions",
  "Права 0777 дают чтение, запись и исполнение любому пользователю системы. Локальный злоумышленник сможет подменить содержимое файла.":
    "0777 grants read, write and execute to every user on the system. A local attacker can replace the file's contents.",
  "Задавайте минимально необходимые права: 0600 для приватных файлов, 0644 для читаемых, 0700 для каталогов.":
    "Set the least permission needed: 0600 for private files, 0644 for readable ones, 0700 for directories.",
  "DES, RC4 и RC2 давно взломаны: короткий ключ или предсказуемый поток позволяют восстановить открытый текст.":
    "DES, RC4 and RC2 have long been broken: a short key or a predictable stream lets an attacker recover the plaintext.",
  'Используйте Cipher.getInstance("AES/GCM/NoPadding") со случайным IV на каждое сообщение.':
    'Use Cipher.getInstance("AES/GCM/NoPadding") with a random IV per message.',
  "Проверка имени хоста TLS отключена": "TLS hostname verification disabled",
  "ALLOW_ALL_HOSTNAME_VERIFIER и NoopHostnameVerifier принимают сертификат для любого домена. Это открывает соединение для man-in-the-middle.":
    "ALLOW_ALL_HOSTNAME_VERIFIER and NoopHostnameVerifier accept a certificate for any domain, opening the connection to a man-in-the-middle.",
  "Уберите кастомный verifier и используйте проверку по умолчанию. Сертификат должен соответствовать хосту.":
    "Remove the custom verifier and use the default check. The certificate must match the host.",
  "CORS разрешён для любого источника": "CORS allows any origin",
  'Разрешённый источник "*" позволяет любому сайту слать запросы с полномочиями пользователя. В связке с cookie это ведёт к краже данных.':
    'An allowed origin of "*" lets any site send requests with the user\'s privileges. Combined with cookies, this leaks data.',
  'Перечислите доверенные источники явным списком вместо "*". Не используйте wildcard с credentials.':
    'List trusted origins explicitly instead of "*". Never use a wildcard together with credentials.',
  "Вывод суперглобала без экранирования (XSS)": "Superglobal echoed without escaping (XSS)",
  "echo/print значения из $_GET, $_POST или $_REQUEST напрямую вставляет пользовательский ввод в HTML — это отражённый XSS.":
    "echo/print of a value from $_GET, $_POST or $_REQUEST puts user input straight into HTML — this is reflected XSS.",
  "Экранируйте вывод через htmlspecialchars($value, ENT_QUOTES) перед вставкой в страницу.":
    "Escape output with htmlspecialchars($value, ENT_QUOTES) before putting it on the page.",
  "extract() на пользовательских данных": "extract() on user input",
  "extract($_GET/$_POST) создаёт переменные по ключам из запроса и может перезаписать уже существующие, подменяя логику и обходя проверки.":
    "extract($_GET/$_POST) creates variables from request keys and can overwrite existing ones, subverting logic and bypassing checks.",
  "Не применяйте extract() к суперглобалам. Читайте нужные поля явно: $id = $_GET['id'].":
    "Do not apply extract() to superglobals. Read the fields you need explicitly: $id = $_GET['id'].",
  "preg_replace с модификатором /e": "preg_replace with the /e modifier",
  "Модификатор /e заставляет preg_replace выполнять замену как код PHP. На данных из запроса это выполнение произвольного кода.":
    "The /e modifier makes preg_replace run the replacement as PHP code. On request data this is arbitrary code execution.",
  "Замените на preg_replace_callback() и формируйте результат в функции обратного вызова без eval.":
    "Switch to preg_replace_callback() and build the result inside the callback without eval.",
  // Ruby/C#/C rules added 16.07.2026 (duplicate titles reuse existing keys)
  "eval() исполняет строку как код Ruby. Если в неё попадают данные извне, это полная компрометация процесса.":
    "eval() runs the string as Ruby code. If external data reaches it, the process is fully compromised.",
  "Уберите eval(). Для выбора поведения используйте хэш-диспетчер или case, для данных — JSON.parse.":
    "Remove eval(). Use a hash dispatch or case for behaviour, and JSON.parse for data.",
  "html_safe / raw отключает экранирование во вью": "html_safe / raw disables escaping in the view",
  "html_safe и raw помечают строку как безопасный HTML, и Rails вставляет её без экранирования. Пользовательский ввод в ней даёт XSS.":
    "html_safe and raw mark a string as safe HTML, so Rails inserts it without escaping. User input in it becomes XSS.",
  "Не вызывайте html_safe на пользовательских данных. Для нужной разметки используйте sanitize с белым списком тегов.":
    "Do not call html_safe on user data. For the markup you need, use sanitize with an allowlist of tags.",
  "Вызов метода по имени из запроса (send)": "Method called by name from the request (send)",
  "send/public_send с именем метода из params позволяет вызвать любой метод объекта, включая приватные, — это обход логики и контроля доступа.":
    "send/public_send with a method name from params can call any method on the object, private ones included — bypassing logic and access control.",
  "Сверяйте имя метода с белым списком перед вызовом или используйте явный case по допустимым действиям.":
    "Check the method name against an allowlist before calling, or use an explicit case over the permitted actions.",
  "Process.Start с cmd.exe, powershell или /bin/sh отдаёт разбор строки шеллу. Подстановка данных извне даёт инъекцию команд.":
    "Process.Start with cmd.exe, powershell or /bin/sh hands the string to a shell. Injecting external data gives command injection.",
  "Запускайте программу напрямую через ProcessStartInfo с Arguments-списком и UseShellExecute = false.":
    "Launch the program directly via ProcessStartInfo with an Arguments list and UseShellExecute = false.",
  "MD5 и SHA-1 подвержены коллизиям и не годятся для подписей и проверки целостности.":
    "MD5 and SHA-1 are collision-prone and unfit for signatures or integrity checks.",
  "Используйте SHA256.Create(). Для паролей — PBKDF2 (Rfc2898DeriveBytes), bcrypt или Argon2.":
    "Use SHA256.Create(). For passwords, use PBKDF2 (Rfc2898DeriveBytes), bcrypt or Argon2.",
  "Устаревшая версия TLS/SSL": "Outdated TLS/SSL version",
  "SSL 3.0 и TLS 1.0/1.1 содержат известные уязвимости (POODLE, BEAST) и выведены из эксплуатации.":
    "SSL 3.0 and TLS 1.0/1.1 have known vulnerabilities (POODLE, BEAST) and are deprecated.",
  "Не задавайте SecurityProtocol вручную — пусть ОС выберет актуальную версию, либо укажите Tls12/Tls13.":
    "Do not set SecurityProtocol by hand — let the OS pick the current version, or specify Tls12/Tls13.",
  'scanf("%s") без ограничения длины': 'scanf("%s") without a length limit',
  "%s в scanf/sscanf без ширины поля читает ввод любой длины в буфер фиксированного размера — переполнение буфера.":
    "%s in scanf/sscanf with no field width reads input of any length into a fixed buffer — a buffer overflow.",
  'Указывайте максимальную ширину: scanf("%63s", buf) для буфера в 64 байта, либо используйте fgets.':
    'Give a maximum width: scanf("%63s", buf) for a 64-byte buffer, or use fgets.',
  "Небезопасное создание временного файла": "Insecure temporary file creation",
  "tmpnam, tempnam и mktemp возвращают имя, но не создают файл атомарно. Между проверкой и открытием возможна подмена (race, символическая ссылка).":
    "tmpnam, tempnam and mktemp return a name but do not create the file atomically. Between the check and the open, it can be swapped (a race, a symlink).",
  "Используйте mkstemp(), который создаёт и открывает файл одним атомарным вызовом.":
    "Use mkstemp(), which creates and opens the file in one atomic call.",
  "rand()/random() — предсказуемые PRNG. Токены, ключи и соли, полученные из них, восстанавливаются по нескольким значениям.":
    "rand()/random() are predictable PRNGs. Tokens, keys and salts drawn from them can be recovered from a few outputs.",
  "Для безопасности используйте getrandom(2), /dev/urandom или arc4random.":
    "For anything security-related use getrandom(2), /dev/urandom or arc4random.",
  // Docker/Shell/CI rules added 16.07.2026
  "ADD с удалённым URL": "ADD with a remote URL",
  "ADD с http(s)-адресом скачивает файл при сборке без проверки контрольной суммы. Подмена источника или MITM втягивают чужое содержимое в образ.":
    "ADD with an http(s) address downloads a file at build time without a checksum. A swapped source or a MITM pulls arbitrary content into the image.",
  "Скачивайте через RUN curl с проверкой суммы, а для локальных файлов используйте COPY — ADD с URL непрозрачен.":
    "Download via RUN curl with a checksum check, and use COPY for local files — ADD with a URL is opaque.",
  "Секрет задан в ENV/ARG": "Secret set in ENV/ARG",
  "Значение ENV или ARG остаётся в слоях образа и в истории сборки. Пароль или токен, заданный так, достанет любой, у кого есть образ.":
    "An ENV or ARG value stays in the image layers and build history. A password or token set this way is readable by anyone who has the image.",
  "Пробрасывайте секреты через RUN --mount=type=secret или переменные окружения при запуске, а не в Dockerfile.":
    "Pass secrets via RUN --mount=type=secret or as environment variables at run time, not in the Dockerfile.",
  "Права 0777 через chmod": "0777 permissions via chmod",
  "chmod 777 даёт чтение, запись и исполнение любому пользователю. Локальный злоумышленник сможет подменить содержимое файла или скрипта.":
    "chmod 777 grants read, write and execute to every user. A local attacker can replace the file or script's contents.",
  "Задавайте минимально необходимые права: 0644 для файлов, 0755 для исполняемых, 0600 для секретов.":
    "Set the least permission needed: 0644 for files, 0755 for executables, 0600 for secrets.",
  "GitHub Actions: инъекция в run через выражение": "GitHub Actions: run injection via expression",
  "Подстановка ${{ github.event.*.title/body }} или github.head_ref прямо в run вставляет подконтрольный атакующему текст в шелл-скрипт шага — это инъекция команд в раннер.":
    "Interpolating ${{ github.event.*.title/body }} or github.head_ref straight into run inserts attacker-controlled text into the step's shell script — command injection on the runner.",
  'Передавайте значение через env: и обращайтесь к нему как "$VAR" в кавычках — тогда подстановка не парсится шеллом.':
    'Pass the value through env: and reference it as "$VAR" in quotes, so the interpolation is not parsed by the shell.',
  "GitHub Actions: permissions write-all": "GitHub Actions: permissions write-all",
  "write-all выдаёт токену workflow права на запись во все области, включая содержимое репозитория. Скомпрометированный шаг сможет пушить код и менять релизы.":
    "write-all gives the workflow token write access to every scope, including repository contents. A compromised step can push code and alter releases.",
  "Задайте минимальные права явно: permissions: { contents: read } на уровне workflow, расширяя точечно там, где нужно.":
    "Set minimal permissions explicitly: permissions: { contents: read } at the workflow level, widening only where needed.",
  // Swift rules added 16.07.2026 (VS-SW-003 reuses the weak-hash title/description)
  "Использование устаревшего UIWebView": "Use of the deprecated UIWebView",
  "UIWebView снят с поддержки Apple и не получает исправлений безопасности. Он не изолирует контент от приложения и уязвим к инъекциям.":
    "UIWebView is deprecated by Apple and no longer gets security fixes. It does not isolate content from the app and is exposed to injection.",
  "Перейдите на WKWebView: он выполняет контент в отдельном процессе и поддерживает современные политики безопасности.":
    "Move to WKWebView: it runs content in a separate process and supports modern security policies.",
  "Инъекция JavaScript во webview": "JavaScript injection into a web view",
  "stringByEvaluatingJavaScriptFromString и evaluateJavaScript с интерполяцией вставляют данные прямо в исполняемый JS. Пользовательский ввод здесь даёт инъекцию скрипта.":
    "stringByEvaluatingJavaScriptFromString and evaluateJavaScript with interpolation insert data straight into executable JS. User input here becomes script injection.",
  "Не собирайте JS из строк. Передавайте данные через WKScriptMessageHandler или postMessage, экранируя значения.":
    "Do not build JS from strings. Pass data through WKScriptMessageHandler or postMessage, escaping the values.",
  "Используйте SHA-256 (CryptoKit: SHA256). Для паролей — bcrypt или Argon2 через проверенную библиотеку.":
    "Use SHA-256 (CryptoKit: SHA256). For passwords, use bcrypt or Argon2 via a vetted library.",
  "Секрет в UserDefaults": "Secret in UserDefaults",
  "UserDefaults хранит данные в незашифрованном plist. Пароль, токен или ключ там доступен любому, кто получит устройство или бэкап.":
    "UserDefaults stores data in an unencrypted plist. A password, token or key there is readable by anyone who gets the device or a backup.",
  "Храните секреты в Keychain (kSecClassGenericPassword), а не в UserDefaults.":
    "Store secrets in the Keychain (kSecClassGenericPassword), not in UserDefaults.",
  // Scala/Perl/Lua/Elixir/Nginx rules added 16.07.2026 (SC-002/003 reuse Java keys)
  "SQL-запрос собирается s-интерполяцией": "SQL query built with s-interpolation",
  "Интерполятор s\"...$x...\" просто вставляет значение в строку, не экранируя его. Переданный так в запрос пользовательский ввод меняет структуру SQL.":
    "The s\"...$x...\" interpolator just drops the value into the string without escaping it. Passed to a query this way, user input changes the SQL structure.",
  "Используйте параметризованные запросы фреймворка: интерполятор sql\"...\" в Slick/Doobie/Anorm подставляет значения как параметры.":
    "Use the framework's parameterized queries: the sql\"...\" interpolator in Slick/Doobie/Anorm binds values as parameters.",
  "Команда с интерполяцией в шелл": "Command interpolated into a shell",
  "Обратные кавычки, system и qx выполняют строку через шелл. Интерполяция переменной в неё даёт инъекцию команд.":
    "Backticks, system and qx run the string through a shell. Interpolating a variable into it gives command injection.",
  "Вызывайте system списком аргументов: system(\"git\", \"log\", $branch) — тогда шелл не участвует.":
    "Call system with an argument list: system(\"git\", \"log\", $branch) — then no shell is involved.",
  "Двухаргументный open с переменной": "Two-argument open with a variable",
  "open(FH, $path) в двухаргументной форме трактует спецсимволы в $path: ведущий или замыкающий | запускает команду, а > < меняют режим. Это инъекция команд и обход доступа.":
    "open(FH, $path) in the two-argument form interprets special characters in $path: a leading or trailing | runs a command, and > < change the mode. That is command injection and access bypass.",
  "Используйте трёхаргументный open с явным режимом: open(my $fh, \"<\", $path).":
    "Use the three-argument open with an explicit mode: open(my $fh, \"<\", $path).",
  "Команда через os.execute / io.popen": "Command via os.execute / io.popen",
  "os.execute и io.popen запускают строку через шелл. Склейка пользовательских данных в неё приводит к инъекции команд.":
    "os.execute and io.popen run the string through a shell. Concatenating user data into it leads to command injection.",
  "Избегайте os.execute с собранной строкой. Проверяйте ввод по белому списку и не передавайте его в шелл.":
    "Avoid os.execute with a built string. Validate input against an allowlist and do not pass it to a shell.",
  "Динамический код через load / loadstring": "Dynamic code via load / loadstring",
  "load и loadstring компилируют строку в функцию. Если в строку попадают внешние данные, это выполнение произвольного кода.":
    "load and loadstring compile a string into a function. If external data reaches the string, it is arbitrary code execution.",
  "Не компилируйте код из данных. Для конфигурации используйте разбор JSON, для поведения — таблицу-диспетчер.":
    "Do not compile code from data. Use JSON parsing for configuration and a dispatch table for behaviour.",
  "Команда через шелл (:os.cmd / System.shell)": "Command via a shell (:os.cmd / System.shell)",
  ":os.cmd и System.shell выполняют строку через системный шелл, интерпретируя метасимволы. Пользовательский ввод в ней даёт инъекцию команд.":
    ":os.cmd and System.shell run the string through the system shell, interpreting metacharacters. User input in it gives command injection.",
  "Используйте System.cmd(\"git\", [\"log\", branch]) со списком аргументов — он не запускает шелл.":
    "Use System.cmd(\"git\", [\"log\", branch]) with an argument list — it starts no shell.",
  "Выполнение кода через Code.eval_string": "Code execution via Code.eval_string",
  "Code.eval_string и Code.eval_quoted компилируют и исполняют переданный код. Внешние данные в аргументе означают выполнение произвольного кода.":
    "Code.eval_string and Code.eval_quoted compile and run the passed code. External data in the argument means arbitrary code execution.",
  "Не выполняйте код из данных. Для динамического выбора используйте apply/3 по проверенному белому списку функций.":
    "Do not run code from data. For a dynamic choice use apply/3 over a vetted allowlist of functions.",
  "Небезопасная десериализация binary_to_term": "Unsafe binary_to_term deserialization",
  ":erlang.binary_to_term без опции :safe воссоздаёт произвольные термы, включая функции и атомы, что ведёт к исчерпанию атомов и выполнению кода.":
    ":erlang.binary_to_term without the :safe option recreates arbitrary terms, including functions and atoms, leading to atom exhaustion and code execution.",
  "Передавайте опцию [:safe]: binary_to_term(data, [:safe]). Недоверенные данные так десериализовать нельзя вовсе.":
    "Pass the [:safe] option: binary_to_term(data, [:safe]). Untrusted data must not be deserialized this way at all.",
  "server_tokens включён": "server_tokens enabled",
  "server_tokens on раскрывает точную версию nginx в заголовках и на страницах ошибок, упрощая подбор известных эксплойтов под неё.":
    "server_tokens on reveals the exact nginx version in headers and error pages, making it easier to match known exploits to it.",
  "Задайте server_tokens off в блоке http.": "Set server_tokens off in the http block.",
  "Устаревшие протоколы TLS": "Outdated TLS protocols",
  "SSLv3 и TLS 1.0/1.1 содержат известные уязвимости (POODLE, BEAST) и выведены из эксплуатации.":
    "SSLv3 and TLS 1.0/1.1 have known vulnerabilities (POODLE, BEAST) and are deprecated.",
  "Оставьте только современные версии: ssl_protocols TLSv1.2 TLSv1.3;":
    "Keep only modern versions: ssl_protocols TLSv1.2 TLSv1.3;",
  "Слабые TLS-шифры": "Weak TLS ciphers",
  "Наборы с NULL, RC4, DES, MD5, EXPORT или aNULL не обеспечивают конфиденциальности и целостности соединения.":
    "Suites with NULL, RC4, DES, MD5, EXPORT or aNULL do not provide confidentiality or integrity for the connection.",
  "Ограничьте ssl_ciphers современными AEAD-наборами и включите ssl_prefer_server_ciphers on.":
    "Restrict ssl_ciphers to modern AEAD suites and enable ssl_prefer_server_ciphers on.",
  "Включён листинг каталога (autoindex)": "Directory listing enabled (autoindex)",
  "autoindex on отдаёт список файлов каталога без index-файла, раскрывая структуру и файлы, которые не предназначались для публикации.":
    "autoindex on returns the directory's file list when there is no index file, exposing the structure and files that were not meant to be public.",
  "Уберите autoindex on там, где листинг не нужен намеренно.":
    "Remove autoindex on where a listing is not deliberately wanted.",
  // Python/JS/Java/Terraform rules added 16.07.2026
  "extractall() — распаковка без проверки путей": "extractall() — extraction without path checks",
  "tarfile.extractall и zipfile.extractall доверяют путям внутри архива. Запись вида ../../etc даёт запись за пределы целевого каталога (Zip Slip).":
    "tarfile.extractall and zipfile.extractall trust the paths inside the archive. An entry like ../../etc writes outside the target directory (Zip Slip).",
  "Проверяйте каждый путь перед распаковкой или используйте tarfile с filter=\"data\" (Python 3.12+), отсекающим выходы за каталог.":
    "Check every path before extracting, or use tarfile with filter=\"data\" (Python 3.12+), which blocks escapes from the directory.",
  "SSTI: render_template_string с данными": "SSTI: render_template_string with data",
  "render_template_string компилирует переданную строку как шаблон Jinja2. Пользовательский ввод в ней приводит к инъекции шаблона и выполнению кода на сервере.":
    "render_template_string compiles the passed string as a Jinja2 template. User input in it leads to template injection and server-side code execution.",
  "Рендерите статические шаблоны из файлов и передавайте данные через контекст, а не собирайте текст шаблона из ввода.":
    "Render static templates from files and pass data through the context, instead of building the template text from input.",
  "JWT: проверка подписи отключена": "JWT: signature verification disabled",
  "verify=False или verify_signature: False заставляет jwt.decode принять токен без проверки подписи. Атакующий сможет подделать любые claims.":
    "verify=False or verify_signature: False makes jwt.decode accept a token without checking the signature. An attacker can forge any claims.",
  "Всегда проверяйте подпись: jwt.decode(token, key, algorithms=[\"RS256\"]). Не отключайте verify_signature.":
    "Always verify the signature: jwt.decode(token, key, algorithms=[\"RS256\"]). Do not disable verify_signature.",
  "mark_safe отключает экранирование (XSS)": "mark_safe disables escaping (XSS)",
  "mark_safe помечает строку как безопасный HTML, и Django вставляет её в шаблон без экранирования. Пользовательский ввод в ней даёт XSS.":
    "mark_safe marks a string as safe HTML, so Django inserts it into the template without escaping. User input in it becomes XSS.",
  "Не вызывайте mark_safe на пользовательских данных. Для нужной разметки используйте bleach.clean с белым списком тегов.":
    "Do not call mark_safe on user data. For the markup you need, use bleach.clean with an allowlist of tags.",
  "SSH: проверка ключа хоста отключена (paramiko)": "SSH: host key check disabled (paramiko)",
  "AutoAddPolicy и WarningPolicy принимают ключ хоста автоматически. Соединение перестаёт защищать от man-in-the-middle.":
    "AutoAddPolicy and WarningPolicy accept the host key automatically. The connection no longer protects against man-in-the-middle.",
  "Используйте RejectPolicy и заранее загруженные known_hosts через load_system_host_keys.":
    "Use RejectPolicy and preloaded known_hosts via load_system_host_keys.",
  "NoSQL-инъекция через $where": "NoSQL injection via $where",
  "Оператор $where в MongoDB выполняет JavaScript на сервере БД. Данные пользователя в его значении дают инъекцию кода и обход фильтров запроса.":
    "MongoDB's $where operator runs JavaScript on the database server. User data in its value gives code injection and bypasses the query filters.",
  "Не используйте $where. Стройте условия обычными операторами ($eq, $in) и приводите типы параметров запроса.":
    "Do not use $where. Build conditions with normal operators ($eq, $in) and coerce the types of query parameters.",
  "SnakeYAML: небезопасная загрузка": "SnakeYAML: unsafe load",
  "new Yaml().load() с конструктором по умолчанию создаёт произвольные Java-объекты по тегам в YAML. На недоверенных данных это ведёт к выполнению кода.":
    "new Yaml().load() with the default constructor builds arbitrary Java objects from tags in the YAML. On untrusted data this leads to code execution.",
  "Создавайте Yaml с SafeConstructor: new Yaml(new SafeConstructor(new LoaderOptions())).":
    "Create Yaml with a SafeConstructor: new Yaml(new SafeConstructor(new LoaderOptions())).",
  "IAM-политика с действием \"*\"": "IAM policy with action \"*\"",
  "Action = \"*\" (часто вместе с Resource \"*\") даёт полный доступ ко всем операциям сервиса. Скомпрометированный принципал получает права администратора.":
    "Action = \"*\" (often together with Resource \"*\") grants full access to every operation of the service. A compromised principal gets admin rights.",
  "Перечислите только нужные действия и ограничьте Resource конкретными ARN — принцип наименьших привилегий.":
    "List only the actions you need and scope Resource to specific ARNs — least privilege.",
  "База данных доступна из интернета": "Database reachable from the internet",
  "publicly_accessible = true выдаёт инстансу БД публичный адрес. В связке с открытой security group это выставляет базу наружу.":
    "publicly_accessible = true gives the database instance a public address. Combined with an open security group it exposes the database to the outside.",
  "Задайте publicly_accessible = false и держите БД в приватной подсети, доступной только из приложения.":
    "Set publicly_accessible = false and keep the database in a private subnet reachable only from the application.",
  "Разрешён IMDSv1 (метаданные без токена)": "IMDSv1 allowed (token-less metadata)",
  "http_tokens = \"optional\" оставляет доступным IMDSv1. При SSRF на инстансе это позволяет украсть временные креды роли через сервис метаданных.":
    "http_tokens = \"optional\" leaves IMDSv1 reachable. With an SSRF on the instance it lets an attacker steal the role's temporary credentials via the metadata service.",
  "Требуйте IMDSv2: в metadata_options задайте http_tokens = \"required\".":
    "Require IMDSv2: set http_tokens = \"required\" in metadata_options.",
  // Vue/Svelte + Go/Ruby/PHP/C# rules added 16.07.2026
  "SSH: проверка ключа хоста отключена": "SSH: host key check disabled",
  "ssh.InsecureIgnoreHostKey принимает любой ключ сервера. Соединение перестаёт защищать от man-in-the-middle.":
    "ssh.InsecureIgnoreHostKey accepts any server key. The connection no longer protects against man-in-the-middle.",
  "Используйте ssh.FixedHostKey или knownhosts.New с заранее известными ключами хостов.":
    "Use ssh.FixedHostKey or knownhosts.New with known host keys.",
  "Открытый редирект через redirect_to": "Open redirect via redirect_to",
  "redirect_to с адресом из params уводит пользователя на произвольный внешний сайт — основа фишинга и обхода доверенных доменов.":
    "redirect_to with an address from params sends the user to an arbitrary external site — the basis of phishing and trusted-domain bypass.",
  "Разрешайте только относительные пути или проверяйте хост по белому списку; в Rails оставляйте allow_other_host по умолчанию выключенным.":
    "Allow only relative paths or check the host against an allowlist; in Rails keep allow_other_host off by default.",
  "Открытый редирект / инъекция заголовка": "Open redirect / header injection",
  "header(\"Location: ...\") с пользовательским вводом даёт открытый редирект, а перевод строки в значении — расщепление HTTP-ответа (HTTP response splitting).":
    "header(\"Location: ...\") with user input gives an open redirect, and a newline in the value gives HTTP response splitting.",
  "Редиректьте только на пути из белого списка и вырезайте переводы строк из значения заголовка.":
    "Redirect only to allowlisted paths and strip newlines from the header value.",
  "assert() со строковым аргументом": "assert() with a string argument",
  "assert() со строкой исполняет её как PHP-код. Пользовательский ввод в этой строке приводит к выполнению произвольного кода.":
    "assert() with a string runs it as PHP code. User input in that string leads to arbitrary code execution.",
  "Не передавайте строки в assert(). Проверяйте условия обычными выражениями и бросайте исключения.":
    "Do not pass strings to assert(). Check conditions with normal expressions and throw exceptions.",
  "Отключена проверка TLS-сертификата (HttpClient)": "TLS certificate validation disabled (HttpClient)",
  "ServerCertificateCustomValidationCallback, возвращающий true, или DangerousAcceptAnyServerCertificateValidator заставляют HttpClient принять любой сертификат — соединение уязвимо к MITM.":
    "A ServerCertificateCustomValidationCallback that returns true, or DangerousAcceptAnyServerCertificateValidator, makes HttpClient accept any certificate — the connection is exposed to MITM.",
  "Уберите колбэк. Для внутреннего CA добавьте его сертификат в доверенное хранилище.":
    "Remove the callback. For an internal CA, add its certificate to the trust store.",
  "Открытый редирект через Response.Redirect": "Open redirect via Response.Redirect",
  "Response.Redirect с адресом из запроса уводит пользователя на произвольный сайт — вектор фишинга и обхода доверенных доменов.":
    "Response.Redirect with an address from the request sends the user to an arbitrary site — a phishing and trusted-domain-bypass vector.",
  "Разрешайте только локальные адреса: проверяйте Url.IsLocalUrl(target) перед редиректом.":
    "Allow only local addresses: check Url.IsLocalUrl(target) before redirecting.",
  "Vue: v-html вставляет сырой HTML": "Vue: v-html inserts raw HTML",
  "Директива v-html рендерит значение как HTML без экранирования. Пользовательские данные в ней приводят к XSS.":
    "The v-html directive renders the value as HTML without escaping. User data in it leads to XSS.",
  "Выводите данные через {{ }} — Vue их экранирует. Для доверенной разметки очищайте её DOMPurify перед вставкой.":
    "Output data with {{ }} — Vue escapes it. For trusted markup, sanitize it with DOMPurify before inserting.",
  "Svelte: {@html} вставляет сырой HTML": "Svelte: {@html} inserts raw HTML",
  "Блок {@html expr} рендерит значение как HTML без экранирования. Пользовательские данные в нём приводят к XSS.":
    "The {@html expr} block renders the value as HTML without escaping. User data in it leads to XSS.",
  "Выводите данные обычной интерполяцией {expr} — Svelte их экранирует. Для доверенной разметки очищайте её DOMPurify.":
    "Output data with normal interpolation {expr} — Svelte escapes it. For trusted markup, sanitize it with DOMPurify.",
  // SQL + Java XXE/ProcessBuilder rules added 17.07.2026
  "xp_cmdshell — выполнение команды ОС": "xp_cmdshell — OS command execution",
  "xp_cmdshell в SQL Server запускает команды операционной системы с правами службы БД. Это прямой путь от SQL-инъекции к захвату сервера.":
    "xp_cmdshell in SQL Server runs operating-system commands with the database service's privileges. It is a direct path from SQL injection to server takeover.",
  "Держите xp_cmdshell отключённым. Для интеграций используйте отдельный сервис, а не команды ОС из БД.":
    "Keep xp_cmdshell disabled. For integrations use a separate service rather than OS commands from the database.",
  "GRANT ALL — избыточные привилегии": "GRANT ALL — excessive privileges",
  "GRANT ALL PRIVILEGES выдаёт учётной записи полный набор прав. Компрометация такого аккаунта означает полный контроль над базой.":
    "GRANT ALL PRIVILEGES gives the account the full set of rights. Compromising such an account means full control over the database.",
  "Выдавайте только нужные права (SELECT/INSERT/UPDATE) на конкретные объекты — принцип наименьших привилегий.":
    "Grant only the rights needed (SELECT/INSERT/UPDATE) on specific objects — least privilege.",
  "Пароль в открытом виде в SQL": "Cleartext password in SQL",
  "IDENTIFIED BY / PASSWORD со строковым литералом сохраняет пароль в тексте миграции и в истории репозитория.":
    "IDENTIFIED BY / PASSWORD with a string literal keeps the password in the migration text and in the repository history.",
  "Заводите учётные записи вне версионируемых миграций или подставляйте пароль из секрет-хранилища при развёртывании.":
    "Create accounts outside versioned migrations, or inject the password from a secret store at deploy time.",
  "Чтение или запись файла из SQL": "File read or write from SQL",
  "INTO OUTFILE/DUMPFILE и LOAD_FILE в MySQL пишут и читают файлы на сервере БД. В связке с инъекцией это ведёт к раскрытию данных и загрузке веб-шелла.":
    "INTO OUTFILE/DUMPFILE and LOAD_FILE in MySQL write and read files on the database server. Combined with injection this leads to data disclosure and web-shell upload.",
  "Отзовите привилегию FILE у прикладных учёток и не используйте файловые операции в запросах приложения.":
    "Revoke the FILE privilege from application accounts and do not use file operations in application queries.",
  "XXE в dom4j/JDOM (SAXReader/SAXBuilder)": "XXE in dom4j/JDOM (SAXReader/SAXBuilder)",
  "SAXReader (dom4j) и SAXBuilder (JDOM) по умолчанию раскрывают внешние сущности XML, что даёт чтение локальных файлов и SSRF.":
    "SAXReader (dom4j) and SAXBuilder (JDOM) resolve external XML entities by default, which allows local file reads and SSRF.",
  "Отключите внешние сущности: setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) на парсере.":
    "Disable external entities: setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) on the parser.",
  "ProcessBuilder запускает шелл": "ProcessBuilder starts a shell",
  "ProcessBuilder с sh -c, bash -c или cmd /c отдаёт разбор строки шеллу. Подстановка данных извне в такую команду даёт инъекцию.":
    "ProcessBuilder with sh -c, bash -c or cmd /c hands the string to a shell. Injecting external data into such a command gives command injection.",
  "Передавайте программу и аргументы отдельными элементами списка, без sh -c: new ProcessBuilder(\"git\", \"log\", branch).":
    "Pass the program and arguments as separate list elements, without sh -c: new ProcessBuilder(\"git\", \"log\", branch).",
  // Secret detectors added 17.07.2026
  "GitLab Personal Access Token": "GitLab Personal Access Token",
  "Токен GitLab даёт доступ к репозиториям и API в объёме своих scope: чтение приватного кода, пуш, управление проектами и CI/CD.":
    "A GitLab token grants repository and API access within its scopes: reading private code, pushing, and managing projects and CI/CD.",
  "Отзовите токен в GitLab (User Settings → Access Tokens) и выпустите новый. Для CI используйте CI/CD-переменные с маскированием.":
    "Revoke the token in GitLab (User Settings → Access Tokens) and issue a new one. For CI use masked CI/CD variables.",
  "npm-токен доступа": "npm access token",
  "Токен npm позволяет публиковать пакеты от вашего имени и читать приватные. Утечка ведёт к компрометации цепочки поставок.":
    "An npm token lets someone publish packages as you and read private ones. A leak compromises the supply chain.",
  "Отзовите токен на npmjs.com (Access Tokens) и выпустите новый. Храните его в CI-секретах, а не в .npmrc в репозитории.":
    "Revoke the token on npmjs.com (Access Tokens) and issue a new one. Keep it in CI secrets, not in a committed .npmrc.",
  "SendGrid API-ключ": "SendGrid API key",
  "Ключ SendGrid позволяет отправлять почту от вашего домена — вектор фишинга и порчи репутации отправителя.":
    "A SendGrid key can send mail from your domain — a phishing and sender-reputation vector.",
  "Отзовите ключ в панели SendGrid (Settings → API Keys) и выпустите новый с минимальными правами.":
    "Revoke the key in the SendGrid dashboard (Settings → API Keys) and issue a new one with minimal scope.",
  "Shopify Access Token": "Shopify Access Token",
  "Токен доступа Shopify даёт доступ к данным магазина: заказам, клиентам и настройкам через Admin API.":
    "A Shopify access token exposes store data — orders, customers and settings — through the Admin API.",
  "Отзовите токен в админке Shopify (Apps → Develop apps) и выпустите новый. Храните его на сервере, а не в клиенте.":
    "Revoke the token in the Shopify admin (Apps → Develop apps) and issue a new one. Keep it on the server, not in the client.",
  "DigitalOcean Personal Access Token": "DigitalOcean Personal Access Token",
  "Токен DigitalOcean управляет вашей инфраструктурой через API: дроплетами, базами, DNS и биллингом.":
    "A DigitalOcean token controls your infrastructure through the API: droplets, databases, DNS and billing.",
  "Отзовите токен в панели DigitalOcean (API → Tokens) и выпустите новый. Храните в переменных окружения.":
    "Revoke the token in the DigitalOcean panel (API → Tokens) and issue a new one. Keep it in environment variables.",
  "Токен загрузки PyPI": "PyPI upload token",
  "Токен PyPI позволяет публиковать пакеты от вашего имени. Утечка ведёт к компрометации цепочки поставок Python.":
    "A PyPI token lets someone publish packages as you. A leak compromises the Python supply chain.",
  "Отзовите токен на pypi.org (Account settings → API tokens) и выпустите новый с областью на конкретный проект.":
    "Revoke the token on pypi.org (Account settings → API tokens) and issue a new one scoped to a single project.",
  "Открыть описание CWE на cwe.mitre.org": "Open the CWE definition on cwe.mitre.org",
  "Вызов eval() с динамическими данными": "eval() call with dynamic data",
  "Вызов exec() с динамическими данными": "exec() call with dynamic data",
  "subprocess с shell=True": "subprocess with shell=True",
  "os.system() — выполнение команды через шелл": "os.system() — command run through a shell",
  "os.popen() — выполнение команды через шелл": "os.popen() — command run through a shell",
  "Десериализация через pickle": "Deserialization via pickle",
  "yaml.load() без безопасного загрузчика": "yaml.load() without a safe loader",
  "SQL-запрос собирается f-строкой": "SQL query built with an f-string",
  "SQL-запрос собирается конкатенацией или %-форматированием": "SQL query built by concatenation or %-formatting",
  "Слабый хеш (MD5/SHA-1)": "Weak hash (MD5/SHA-1)",
  "Отключена проверка TLS-сертификата": "TLS certificate verification disabled",
  "Отключена проверка hostname в ssl": "SSL hostname verification disabled",
  "Flask запущен с debug=True": "Flask running with debug=True",
  "Разбор XML уязвим к XXE и bomb-атакам": "XML parsing vulnerable to XXE and bomb attacks",
  "Слабый генератор случайных чисел для секретов": "Weak random generator for secrets",
  "tempfile.mktemp() — гонка при создании файла": "tempfile.mktemp() — race on file creation",
  "Jinja2 с отключённым автоэкранированием": "Jinja2 with autoescaping disabled",
  "assert используется для контроля доступа": "assert used for access control",
  "Django запущен с DEBUG = True": "Django running with DEBUG = True",
  "Привязка сервера ко всем интерфейсам": "Server bound to all interfaces",
  "Права 0777 на файл или каталог": "0777 permissions on a file or directory",
  "Вызов eval()": "eval() call",
  "Конструктор Function() из строки": "Function() constructor from a string",
  "Присваивание в innerHTML / outerHTML": "Assignment to innerHTML / outerHTML",
  "insertAdjacentHTML с динамическими данными": "insertAdjacentHTML with dynamic data",
  "child_process.exec() — команда через шелл": "child_process.exec() — command through a shell",
  "spawn/execFile с shell: true": "spawn/execFile with shell: true",
  "SQL-запрос собирается шаблонной строкой": "SQL query built with a template literal",
  "SQL-запрос собирается конкатенацией": "SQL query built by concatenation",
  "Отключена проверка TLS через NODE_TLS_REJECT_UNAUTHORIZED": "TLS verification disabled via NODE_TLS_REJECT_UNAUTHORIZED",
  "JWT: разрешён алгоритм none или не задан список алгоритмов": "JWT: 'none' algorithm allowed or no algorithm list set",
  "jwt.decode() вместо jwt.verify()": "jwt.decode() instead of jwt.verify()",
  "Math.random() для токена или идентификатора сессии": "Math.random() for a token or session id",
  "Устаревший crypto.createCipher()": "Deprecated crypto.createCipher()",
  "Слабый хеш (MD5/SHA-1) в crypto": "Weak hash (MD5/SHA-1) in crypto",
  "CORS: разрешены все источники": "CORS: all origins allowed",
  "postMessage с целевым источником *": "postMessage with target origin *",
  "Открытый редирект из пользовательских данных": "Open redirect from user data",
  "Path traversal: путь из пользовательских данных": "Path traversal: path from user data",
  "setTimeout/setInterval со строкой вместо функции": "setTimeout/setInterval with a string instead of a function",
  "target=\"_blank\" без rel=\"noopener\"": "target=\"_blank\" without rel=\"noopener\"",
  "Токен хранится в localStorage": "Token stored in localStorage",
  "Cookie без флагов httpOnly / secure": "Cookie without httpOnly / secure flags",
  "Небезопасная десериализация через node-serialize": "Unsafe deserialization via node-serialize",
  "Модуль vm не является песочницей": "The vm module is not a sandbox",
  "Регулярное выражение с риском катастрофического бэктрекинга (ReDoS)": "Regular expression at risk of catastrophic backtracking (ReDoS)",
  "Блок unsafe": "unsafe block",
  "from_utf8_unchecked без проверки": "from_utf8_unchecked without validation",
  "get_unchecked — доступ без проверки границ": "get_unchecked — access without bounds checking",
  "Команда запускается через шелл (sh -c / cmd /C)": "Command run through a shell (sh -c / cmd /C)",
  "reqwest принимает недействительные сертификаты": "reqwest accepts invalid certificates",
  "SQL-запрос собирается format!": "SQL query built with format!",
  "unwrap() на результате разбора внешних данных": "unwrap() on parsed external data",
  "Арифметика без контроля переполнения": "Arithmetic without overflow checks",
  "Контейнер работает от root": "Container runs as root",
  "Скачивание скрипта и запуск через пайп": "Downloading a script and piping it to a shell",
  "Загрузка с отключённой проверкой сертификата": "Download with certificate verification disabled",
  "Базовый образ с тегом latest": "Base image with the latest tag",
  "eval в shell-скрипте": "eval in a shell script",
  "GitHub Actions: сторонний action не зафиксирован по SHA": "GitHub Actions: third-party action not pinned by SHA",
  "Команда запускается через шелл": "Command run through a shell",
  "SQL-запрос собирается конкатенацией или Sprintf": "SQL query built by concatenation or Sprintf",
  "Ошибка игнорируется присваиванием в _": "Error ignored by assigning to _",
  "Слабый генератор случайных чисел": "Weak random number generator",
  "Runtime.exec() — выполнение внешней команды": "Runtime.exec() — running an external command",
  "Десериализация через ObjectInputStream": "Deserialization via ObjectInputStream",
  "Разбор XML уязвим к XXE": "XML parsing vulnerable to XXE",
  "Шифрование в режиме ECB": "Encryption in ECB mode",
  "eval() — выполнение произвольного кода": "eval() — arbitrary code execution",
  "Выполнение системной команды": "System command execution",
  "SQL-запрос собирается интерполяцией": "SQL query built by interpolation",
  "Небезопасная десериализация": "Unsafe deserialization",
  "Подключение файла по переменной (LFI/RFI)": "File inclusion via a variable (LFI/RFI)",
  "Выполнение команды через шелл": "Command execution through a shell",
  "Небезопасная десериализация YAML/Marshal": "Unsafe YAML/Marshal deserialization",
  "SQL-запрос собирается конкатенацией или интерполяцией": "SQL query built by concatenation or interpolation",
  "Небезопасная десериализация BinaryFormatter": "Unsafe BinaryFormatter deserialization",
  "Небезопасная функция копирования строк": "Unsafe string copy function",
  "Форматная строка из переменной": "Format string from a variable",
  "Вызов system() с собранной строкой": "system() call with a built string",
  "Ресурс открыт всему интернету": "Resource open to the whole internet",
  "Публичный доступ к бакету": "Public bucket access",
  "Шифрование отключено": "Encryption disabled",
  "Секрет в открытом виде в конфигурации": "Secret in plaintext in configuration",
  "Контейнер запущен привилегированным": "Container running privileged",
  "Разрешено повышение привилегий": "Privilege escalation allowed",
  "Монтирование хостовой файловой системы": "Host filesystem mounted",
  "Invoke-Expression с собранной строкой": "Invoke-Expression with a built string",
  "Выполнение кода": "Code execution",
  "Инъекция команд": "Command injection",
  "SQL-инъекция": "SQL injection",
  "Криптография": "Cryptography",
  "Транспортная безопасность": "Transport security",
  "Конфигурация": "Configuration",
  "Работа с файлами": "File handling",
  "Контроль доступа": "Access control",
  "Аутентификация": "Authentication",
  "Утечка данных": "Data exposure",
  "Открытый редирект": "Open redirect",
  "Хранение секретов": "Secret storage",
  "Отказ в обслуживании": "Denial of service",
  "Безопасность памяти": "Memory safety",
  "Обработка ошибок": "Error handling",
  "Целочисленное переполнение": "Integer overflow",
  "Цепочка поставок": "Supply chain",
  "Секрет в коде": "Secret in code",
  "AWS Access Key ID в коде": "AWS Access Key ID in code",
  "AWS Secret Access Key в коде": "AWS Secret Access Key in code",
  "Приватный криптографический ключ": "Private cryptographic key",
  "Slack-токен": "Slack token",
  "Stripe API-ключ": "Stripe API key",
  "Google API-ключ": "Google API key",
  "Строка подключения к БД с паролем": "Database connection string with a password",
  "Токен Telegram-бота": "Telegram bot token",
  "OpenAI / Anthropic API-ключ": "OpenAI / Anthropic API key",
  "Пароль зашит в код": "Password hardcoded in code",
  "Обобщённый API-ключ или токен в коде": "Generic API key or token in code",
  "JWT с полезной нагрузкой в коде": "JWT with payload in code",
  "Поиск секретов": "Secret scanning",
  "Бинарный файл (нечего анализировать)": "Binary file (nothing to analyse)",
  "Содержимое не является текстом": "Content is not text",
  "Медиафайл": "Media file",
  "Архив": "Archive",
  "Файл слишком большой": "File too large",
  "Минифицированный или сгенерированный код": "Minified or generated code",
  "Сторонние зависимости (vendor)": "Third-party dependencies (vendor)",
  "Lock-файл: проверен только на CVE": "Lock file: checked for CVEs only",
  "Не удалось прочитать файл": "Could not read the file",
  "eval() выполняет переданную строку как код Python. Если в неё попадают данные от пользователя, атакующий получает выполнение произвольного кода в процессе приложения.": "eval() runs the given string as Python code. If user data reaches it, an attacker gains arbitrary code execution inside the application process.",
  "exec() исполняет произвольный код Python. Любое влияние пользователя на аргумент означает полную компрометацию процесса.": "exec() runs arbitrary Python code. Any user influence over the argument means full compromise of the process.",
  "shell=True запускает команду через системный шелл, поэтому метасимволы (; | & $() ``) в аргументах интерпретируются. Подстановка пользовательских данных даёт инъекцию команд.": "shell=True runs the command through the system shell, so metacharacters (; | & $() ``) in arguments are interpreted. Injecting user data leads to command injection.",
  "os.system() всегда идёт через шелл и не умеет экранировать аргументы. Это классический вектор инъекции команд.": "os.system() always goes through the shell and cannot escape arguments. It is a classic command-injection vector.",
  "os.popen() запускает строку в шелле. Пользовательский ввод в этой строке приводит к инъекции команд.": "os.popen() runs the string in a shell. User input in that string leads to command injection.",
  "pickle.load()/loads() при разборе данных вызывает конструкторы объектов и может выполнить произвольный код. Формат не предназначен для недоверенных данных.": "pickle.load()/loads() invokes object constructors while parsing and can run arbitrary code. The format is not meant for untrusted data.",
  "Загрузчик по умолчанию в PyYAML умеет конструировать произвольные объекты Python, что даёт выполнение кода при разборе недоверенного YAML.": "PyYAML's default loader can construct arbitrary Python objects, giving code execution when parsing untrusted YAML.",
  "Подстановка значений в текст SQL через f-строку не экранирует кавычки и спецсимволы. Пользовательский ввод может изменить структуру запроса — это SQL-инъекция.": "Inserting values into SQL text with an f-string does not escape quotes or special characters. User input can change the query structure — that is SQL injection.",
  "Склейка пользовательских данных с текстом SQL через + или % позволяет атакующему дописать собственные конструкции в запрос.": "Concatenating user data into SQL text with + or % lets an attacker append their own clauses to the query.",
  "MD5 и SHA-1 уязвимы к коллизиям и не годятся для подписей, проверки целостности и хранения паролей.": "MD5 and SHA-1 are vulnerable to collisions and are unfit for signatures, integrity checks, or password storage.",
  "verify=False заставляет requests принимать любой сертификат. Соединение перестаёт защищать от man-in-the-middle: трафик можно прочитать и подменить.": "verify=False makes requests accept any certificate. The connection no longer protects against man-in-the-middle: traffic can be read and tampered with.",
  "check_hostname=False или CERT_NONE снимает проверку того, что сертификат выдан именно тому хосту, к которому идёт подключение.": "check_hostname=False or CERT_NONE removes the check that the certificate was issued for the host being connected to.",
  "Debug-режим Flask включает интерактивную консоль Werkzeug. На доступном извне хосте это прямое выполнение кода без аутентификации.": "Flask debug mode enables the interactive Werkzeug console. On an externally reachable host this is direct code execution without authentication.",
  "Стандартные парсеры xml.etree, minidom и lxml по умолчанию могут раскрывать внешние сущности — это чтение локальных файлов и SSRF, а также exponential entity expansion.": "The standard xml.etree, minidom and lxml parsers may resolve external entities by default — enabling local file reads, SSRF, and exponential entity expansion.",
  "Модуль random — предсказуемый PRNG (Mersenne Twister). Токены, пароли и ключи, полученные из него, восстанавливаются по нескольким выданным значениям.": "The random module is a predictable PRNG (Mersenne Twister). Tokens, passwords and keys derived from it can be recovered from a few emitted values.",
  "mktemp() только возвращает имя, не создавая файл. Между проверкой и созданием другой процесс может подставить симлинк (TOCTOU).": "mktemp() only returns a name without creating the file. Between the check and the create, another process can slip in a symlink (TOCTOU).",
  "autoescape=False означает, что переменные вставляются в HTML как есть. Любые пользовательские данные в шаблоне становятся XSS.": "autoescape=False means variables are inserted into HTML as-is. Any user data in the template becomes XSS.",
  "Интерпретатор с флагом -O полностью удаляет assert. Если на нём держится проверка прав, в оптимизированной сборке она просто исчезнет.": "The interpreter's -O flag removes assert entirely. If an access check relies on it, it simply vanishes in an optimized build.",
  "При DEBUG=True Django на любой ошибке отдаёт трейсбек с фрагментами кода, настройками и значениями переменных окружения.": "With DEBUG=True, Django returns a traceback on any error, exposing code snippets, settings, and environment variable values.",
  "0.0.0.0 открывает порт на всех сетевых интерфейсах, включая внешние. Часто это делают для отладки и забывают вернуть обратно.": "0.0.0.0 opens the port on every network interface, including external ones. This is often done for debugging and left in by mistake.",
  "chmod 0777 даёт запись любому локальному пользователю. Исполняемый файл или скрипт с такими правами можно подменить.": "chmod 0777 grants write access to any local user. An executable or script with such permissions can be replaced.",
  "eval() исполняет строку как JavaScript в текущей области видимости. С данными от пользователя это выполнение произвольного кода и кража сессии.": "eval() runs the string as JavaScript in the current scope. With user data this means arbitrary code execution and session theft.",
  "new Function(str) компилирует строку в функцию — это тот же eval, только через другой вход, и он так же обходится CSP-политикой без unsafe-eval.": "new Function(str) compiles a string into a function — the same as eval through another entry point, and it is likewise blocked by a CSP without unsafe-eval.",
  "Этот проп отключает экранирование React и вставляет HTML как есть. Если строка содержит пользовательские данные, это XSS.": "This prop turns off React's escaping and inserts HTML as-is. If the string contains user data, it is XSS.",
  "innerHTML парсит строку как HTML. Пользовательские данные в ней приводят к XSS: скрипт исполнится в контексте вашего домена.": "innerHTML parses the string as HTML. User data in it leads to XSS: the script runs in your domain's context.",
  "Метод вставляет строку как разметку, минуя экранирование. Тот же вектор XSS, что и innerHTML.": "The method inserts the string as markup, bypassing escaping. The same XSS vector as innerHTML.",
  "document.write() пишет строку прямо в поток документа как HTML. Это и XSS-вектор, и причина блокировки парсера.": "document.write() writes the string straight into the document stream as HTML. It is both an XSS vector and a cause of parser blocking.",
  "exec() передаёт строку системному шеллу целиком. Пользовательские данные в команде дают инъекцию: `; rm -rf /` отработает.": "exec() passes the whole string to the system shell. User data in the command means injection: `; rm -rf /` will run.",
  "Опция shell:true возвращает разбор аргументов шеллу и сводит на нет главное преимущество spawn перед exec.": "The shell:true option hands argument parsing back to the shell, negating spawn's main advantage over exec.",
  "Интерполяция ${...} в тексте SQL не экранирует кавычки. Пользовательский ввод меняет структуру запроса — SQL-инъекция.": "${...} interpolation in SQL text does not escape quotes. User input changes the query structure — SQL injection.",
  "Склейка SQL со значениями через + позволяет атакующему дописать в запрос свои условия или подзапросы.": "Concatenating values into SQL with + lets an attacker append their own conditions or subqueries.",
  "Значение 0 глобально отключает проверку сертификатов для всего процесса Node. Все исходящие HTTPS-соединения становятся уязвимы к MITM.": "A value of 0 globally disables certificate verification for the whole Node process. Every outgoing HTTPS connection becomes vulnerable to MITM.",
  "Опция отключает проверку цепочки сертификатов для конкретного соединения — трафик можно перехватить и подменить.": "The option disables certificate-chain verification for a specific connection — traffic can be intercepted and tampered with.",
  "Алгоритм none означает подпись без ключа — токен можно подделать целиком. Отсутствие явного списка алгоритмов открывает атаку смены алгоритма (RS256 → HS256).": "The 'none' algorithm means an unsigned token — it can be forged entirely. Missing an explicit algorithm list opens the algorithm-confusion attack (RS256 → HS256).",
  "decode() читает содержимое токена, но не проверяет подпись. Доверять таким данным нельзя — их может подделать кто угодно.": "decode() reads the token's contents but does not verify the signature. Such data cannot be trusted — anyone can forge it.",
  "Math.random() не криптостойкий: состояние генератора восстанавливается по нескольким значениям, а значит токены предсказуемы.": "Math.random() is not cryptographically strong: the generator's state can be recovered from a few values, so tokens are predictable.",
  "createCipher() выводит ключ из пароля слабой схемой и работает без IV, что даёт повторяющийся шифротекст для одинаковых данных.": "createCipher() derives a key from a password with a weak scheme and runs without an IV, producing repeating ciphertext for identical data.",
  "MD5 и SHA-1 подвержены коллизиям, их нельзя применять для подписей и проверки целостности.": "MD5 and SHA-1 are collision-prone and must not be used for signatures or integrity checks.",
  "origin \"*\" разрешает любому сайту читать ответы вашего API. В связке с credentials:true это позволяет чужой странице действовать от имени залогиненного пользователя.": "origin \"*\" lets any site read your API responses. Combined with credentials:true it lets a foreign page act on behalf of a logged-in user.",
  "Указание \"*\" отправляет сообщение любому окну, которое сейчас загружено во фрейм. Если там чужой сайт, он прочитает данные.": "Specifying \"*\" sends the message to whatever window is currently loaded in the frame. If a foreign site is there, it reads the data.",
  "Редирект по адресу из запроса позволяет увести пользователя на фишинговый сайт по ссылке с вашего домена.": "Redirecting to an address from the request lets a link on your domain send the user to a phishing site.",
  "Склейка пути с данными запроса позволяет выйти за пределы каталога через ../ и прочитать произвольные файлы.": "Joining a path with request data allows escaping the directory via ../ and reading arbitrary files.",
  "Если первым аргументом передана строка, она исполняется как код — это скрытый eval.": "If the first argument is a string, it is run as code — a hidden eval.",
  "Открытая вкладка получает доступ к window.opener и может подменить исходную страницу на фишинговую (reverse tabnabbing).": "The opened tab gains access to window.opener and can replace the original page with a phishing one (reverse tabnabbing).",
  "localStorage доступен любому скрипту на странице. Одна XSS — и токен утёк. В отличие от cookie, флаг HttpOnly здесь недоступен.": "localStorage is readable by any script on the page. One XSS and the token leaks. Unlike a cookie, the HttpOnly flag is unavailable here.",
  "Без httpOnly cookie читается скриптом при XSS, без secure — уходит по открытому HTTP и перехватывается в сети.": "Without httpOnly the cookie is readable by script during XSS; without secure it goes over plain HTTP and is intercepted on the network.",
  "unserialize() в node-serialize исполняет функции, закодированные в данных. Это известный вектор RCE.": "unserialize() in node-serialize runs functions encoded in the data. It is a known RCE vector.",
  "vm.runInNewContext() не изолирует код: через конструкторы и прототипы из него можно выбраться в основной контекст процесса.": "vm.runInNewContext() does not isolate code: via constructors and prototypes one can escape into the main process context.",
  "Вложенные квантификаторы вида (a+)+ на специально подобранной строке приводят к экспоненциальному времени разбора и блокируют event loop.": "Nested quantifiers like (a+)+ on a crafted string lead to exponential parse time and block the event loop.",
  "В unsafe компилятор не проверяет корректность работы с памятью. Ошибка здесь — это UB: порча памяти, эксплуатируемые падения.": "Inside unsafe the compiler does not check memory correctness. A mistake here is UB: memory corruption and exploitable crashes.",
  "transmute переинтерпретирует байты одного типа как другой без каких-либо проверок. Несовпадение размера или инвариантов типа — мгновенное UB.": "transmute reinterprets one type's bytes as another with no checks. A mismatch in size or type invariants is instant UB.",
  "Функция создаёт &str из байтов, не проверяя UTF-8. Невалидные байты ломают инвариант str и приводят к UB при дальнейшей работе со строкой.": "The function builds a &str from bytes without checking UTF-8. Invalid bytes break the str invariant and cause UB in later string operations.",
  "Метод читает элемент без проверки индекса. Выход за границы даёт чтение чужой памяти или падение — это UB, а не паника.": "The method reads an element without bounds checking. Going out of range reads foreign memory or crashes — this is UB, not a panic.",
  "Передача строки в sh -c возвращает разбор метасимволов шеллу. Пользовательские данные в такой строке дают инъекцию команд.": "Passing a string to sh -c hands metacharacter parsing to the shell. User data in that string means command injection.",
  "danger_accept_invalid_certs(true) отключает проверку сертификата. Соединение больше не защищено от man-in-the-middle.": "danger_accept_invalid_certs(true) disables certificate verification. The connection is no longer protected against man-in-the-middle.",
  "format! не экранирует кавычки, поэтому подстановка пользовательских данных в текст SQL приводит к инъекции.": "format! does not escape quotes, so inserting user data into SQL text leads to injection.",
  "MD5 и SHA-1 уязвимы к коллизиям и не годятся для подписей и проверки целостности.": "MD5 and SHA-1 are vulnerable to collisions and unfit for signatures or integrity checks.",
  "unwrap() на данных извне (переменные окружения, парсинг ввода, сеть) превращает некорректный вход в панику. Для сервиса это отказ в обслуживании.": "unwrap() on external data (environment variables, input parsing, network) turns bad input into a panic. For a service that is a denial of service.",
  "В release-сборке переполнение целого молча заворачивается по модулю. В расчётах размеров, индексов и балансов это приводит к логическим ошибкам и порче памяти.": "In a release build, integer overflow silently wraps. In size, index and balance calculations this leads to logic errors and memory corruption.",
  "Без директивы USER процесс в контейнере идёт от root. При побеге из контейнера или монтировании томов это заметно повышает ущерб.": "Without a USER directive the container process runs as root. On a container escape or with mounted volumes this greatly increases the damage.",
  "curl | sh выполняет всё, что вернёт сервер, без проверки. Компрометация источника или MITM означают выполнение произвольного кода при сборке.": "curl | sh runs whatever the server returns, unchecked. A compromised source or MITM means arbitrary code execution during the build.",
  "Флаги --no-check-certificate и --insecure отключают проверку TLS при скачивании — содержимое можно подменить по пути.": "The --no-check-certificate and --insecure flags disable TLS verification on download — the content can be swapped in transit.",
  "latest не фиксирует версию: сборка невоспроизводима, а обновление базового образа может незаметно втянуть уязвимость.": "latest does not pin a version: the build is not reproducible, and a base-image update can silently pull in a vulnerability.",
  "eval исполняет собранную строку как команду. Любая переменная внутри неё, пришедшая извне, даёт инъекцию.": "eval runs the built string as a command. Any variable in it that comes from outside means injection.",
  "Этот триггер даёт workflow доступ к секретам репозитория и выполняется в контексте базовой ветки. В связке с checkout кода из PR любой внешний контрибьютор может украсть секреты.": "This trigger grants the workflow access to repository secrets and runs in the base branch's context. Combined with checking out PR code, any external contributor can steal secrets.",
  "Ссылка на тег или ветку означает, что владелец action может в любой момент подменить код, который выполняется с вашими секретами.": "Referencing a tag or branch means the action's owner can swap the code that runs with your secrets at any time.",
  "exec.Command(\"sh\", \"-c\", ...) отдаёт разбор строки шеллу, поэтому метасимволы в аргументах интерпретируются. Пользовательский ввод даёт инъекцию команд.": "exec.Command(\"sh\", \"-c\", ...) hands string parsing to the shell, so metacharacters in arguments are interpreted. User input means command injection.",
  "Склейка значений с текстом SQL не экранирует кавычки, поэтому пользовательский ввод может изменить структуру запроса.": "Concatenating values into SQL text does not escape quotes, so user input can change the query structure.",
  "InsecureSkipVerify: true заставляет клиент принимать любой сертификат. Соединение перестаёт защищать от man-in-the-middle.": "InsecureSkipVerify: true makes the client accept any certificate. The connection no longer protects against man-in-the-middle.",
  "Go возвращает ошибки значением. Присваивание в _ отбрасывает её молча, и код продолжает работать с неинициализированными данными.": "Go returns errors as values. Assigning to _ discards it silently, and the code continues with uninitialized data.",
  "math/rand — предсказуемый PRNG. Токены и ключи, полученные из него, восстанавливаются по нескольким значениям.": "math/rand is a predictable PRNG. Tokens and keys derived from it can be recovered from a few values.",
  "Передача собранной строки в Runtime.exec() позволяет подставить в неё пользовательские данные, что даёт инъекцию команд.": "Passing a built string to Runtime.exec() allows user data to be inserted, giving command injection.",
  "Склейка значений с текстом SQL через + позволяет атакующему дописать свои конструкции в запрос.": "Concatenating values into SQL text with + lets an attacker append their own clauses to the query.",
  "readObject() восстанавливает произвольные классы и вызывает их методы. На недоверенных данных это классический вектор RCE в Java.": "readObject() reconstructs arbitrary classes and calls their methods. On untrusted data this is a classic Java RCE vector.",
  "Парсеры XML в Java по умолчанию раскрывают внешние сущности, что даёт чтение локальных файлов и SSRF.": "Java's XML parsers resolve external entities by default, enabling local file reads and SSRF.",
  "ECB шифрует одинаковые блоки одинаково, поэтому структура открытого текста видна в шифротексте.": "ECB encrypts identical blocks identically, so the plaintext structure is visible in the ciphertext.",
  "eval() исполняет строку как PHP. Любое влияние пользователя на аргумент означает полную компрометацию.": "eval() runs the string as PHP. Any user influence over the argument means full compromise.",
  "system(), exec(), shell_exec() и passthru() запускают команду через шелл. Пользовательский ввод в аргументе даёт инъекцию.": "system(), exec(), shell_exec() and passthru() run the command through a shell. User input in the argument means injection.",
  "Подстановка переменных в текст SQL не экранирует кавычки — это SQL-инъекция.": "Inserting variables into SQL text does not escape quotes — that is SQL injection.",
  "unserialize() на недоверенных данных вызывает магические методы объектов и приводит к выполнению кода (POP-цепочки).": "unserialize() on untrusted data triggers objects' magic methods and leads to code execution (POP chains).",
  "include/require с переменной в пути позволяет подключить произвольный файл, а при allow_url_include — и удалённый.": "include/require with a variable in the path lets an arbitrary file be included — and a remote one when allow_url_include is on.",
  "Обратные кавычки, system() и %x запускают команду через шелл. Интерполяция пользовательских данных даёт инъекцию.": "Backticks, system() and %x run the command through a shell. Interpolating user data means injection.",
  "Интерполяция #{} в where/find_by_sql не экранирует значения — это SQL-инъекция в Rails.": "#{} interpolation in where/find_by_sql does not escape values — that is SQL injection in Rails.",
  "YAML.load и Marshal.load восстанавливают произвольные объекты Ruby и приводят к выполнению кода.": "YAML.load and Marshal.load reconstruct arbitrary Ruby objects and lead to code execution.",
  "Склейка значений с текстом SQL не экранирует кавычки — пользовательский ввод меняет структуру запроса.": "Concatenating values into SQL text does not escape quotes — user input changes the query structure.",
  "BinaryFormatter восстанавливает произвольные типы и признан небезопасным самим Microsoft — он удалён в .NET 9.": "BinaryFormatter reconstructs arbitrary types and is deemed unsafe by Microsoft itself — it was removed in .NET 9.",
  "Возврат true из ServerCertificateValidationCallback принимает любой сертификат — соединение уязвимо к MITM.": "Returning true from ServerCertificateValidationCallback accepts any certificate — the connection is vulnerable to MITM.",
  "strcpy, strcat, sprintf и gets не проверяют размер буфера. Это классическое переполнение буфера с перезаписью стека.": "strcpy, strcat, sprintf and gets do not check buffer size. This is a classic buffer overflow overwriting the stack.",
  "printf(var) вместо printf(\"%s\", var) позволяет через %n и %x читать и писать память — это атака на форматную строку.": "printf(var) instead of printf(\"%s\", var) allows reading and writing memory via %n and %x — a format-string attack.",
  "system() выполняет команду через шелл. Данные извне в этой строке дают инъекцию команд.": "system() runs the command through a shell. External data in that string means command injection.",
  "0.0.0.0/0 в правиле безопасности открывает порт для всего интернета. Для SSH, RDP или БД это прямой путь к перебору и эксплуатации.": "0.0.0.0/0 in a security rule opens the port to the whole internet. For SSH, RDP or a database this is a direct path to brute-forcing and exploitation.",
  "acl = \"public-read\" делает содержимое бакета доступным любому. Это самая частая причина утечек данных в облаках.": "acl = \"public-read\" makes the bucket contents available to anyone. It is the most common cause of cloud data leaks.",
  "Явное отключение шифрования оставляет данные в хранилище в открытом виде.": "Explicitly disabling encryption leaves the data at rest in plaintext.",
  "Пароли и ключи в .tf попадают в репозиторий и в state-файл. Terraform state хранит их без шифрования.": "Passwords and keys in .tf end up in the repository and the state file. Terraform state stores them unencrypted.",
  "privileged: true даёт контейнеру доступ ко всем устройствам хоста и снимает почти всю изоляцию. Побег из такого контейнера тривиален.": "privileged: true gives the container access to all host devices and removes almost all isolation. Escaping such a container is trivial.",
  "allowPrivilegeEscalation: true позволяет процессу получить больше прав, чем у родителя, через setuid-бинарники.": "allowPrivilegeEscalation: true lets a process gain more privileges than its parent via setuid binaries.",
  "hostPath пробрасывает каталог узла в контейнер. Монтирование / или /var/run/docker.sock равносильно выдаче прав root на узле.": "hostPath exposes a node directory to the container. Mounting / or /var/run/docker.sock is equivalent to granting root on the node.",
  "runAsUser: 0 запускает процесс от root внутри контейнера, что усиливает последствия любой уязвимости в нём.": "runAsUser: 0 runs the process as root inside the container, amplifying the impact of any vulnerability in it.",
  "Invoke-Expression исполняет строку как код PowerShell — это прямой аналог eval.": "Invoke-Expression runs the string as PowerShell code — a direct equivalent of eval.",
  "SkipCertificateCheck и подмена CertificatePolicy принимают любой сертификат — трафик можно перехватить.": "SkipCertificateCheck and overriding CertificatePolicy accept any certificate — traffic can be intercepted.",
  "Уберите eval(). Для разбора данных используйте json.loads(), для literal-структур — ast.literal_eval(), для диспетчеризации — словарь функций.": "Remove eval(). Use json.loads() to parse data, ast.literal_eval() for literal structures, and a function dictionary for dispatch.",
  "Замените exec() явной логикой: словарь-диспетчер, importlib для загрузки модулей из белого списка.": "Replace exec() with explicit logic: a dispatch dictionary, or importlib to load modules from an allowlist.",
  "Уберите shell=True и передавайте команду списком аргументов: subprocess.run([\"ls\", \"-l\", path]). Тогда аргументы не парсятся шеллом.": "Remove shell=True and pass the command as an argument list: subprocess.run([\"ls\", \"-l\", path]). Then the arguments are not parsed by a shell.",
  "Используйте subprocess.run([...]) со списком аргументов и без shell=True.": "Use subprocess.run([...]) with an argument list and without shell=True.",
  "Перейдите на subprocess.run([...], capture_output=True) без shell=True.": "Switch to subprocess.run([...], capture_output=True) without shell=True.",
  "Для обмена данными используйте JSON. Если pickle необходим — принимайте его только из доверенного источника и подписывайте (HMAC).": "Use JSON for data exchange. If pickle is required, accept it only from a trusted source and sign it (HMAC).",
  "Используйте yaml.safe_load(data) или явно yaml.load(data, Loader=yaml.SafeLoader).": "Use yaml.safe_load(data) or explicitly yaml.load(data, Loader=yaml.SafeLoader).",
  "Используйте параметризованные запросы: cursor.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,)). Драйвер сам выполнит экранирование.": "Use parameterized queries: cursor.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,)). The driver handles escaping.",
  "Передавайте значения отдельным параметром: cursor.execute(query, params). Никогда не форматируйте SQL строками.": "Pass values as a separate parameter: cursor.execute(query, params). Never format SQL with strings.",
  "Для целостности берите hashlib.sha256. Для паролей — bcrypt, scrypt или argon2 (passlib/argon2-cffi), никогда не «сырой» хеш. Если хеш используется не для безопасности, добавьте usedforsecurity=False.": "For integrity use hashlib.sha256. For passwords use bcrypt, scrypt or argon2 (passlib/argon2-cffi), never a raw hash. If the hash is not security-related, add usedforsecurity=False.",
  "Уберите verify=False. Для внутреннего CA укажите путь к его сертификату: requests.get(url, verify=\"/path/ca.pem\").": "Remove verify=False. For an internal CA, point to its certificate: requests.get(url, verify=\"/path/ca.pem\").",
  "Оставьте контекст по умолчанию: ssl.create_default_context(). Он включает и проверку цепочки, и проверку hostname.": "Keep the default context: ssl.create_default_context(). It enables both chain and hostname verification.",
  "Никогда не включайте debug в продакшене. Управляйте флагом через переменную окружения и по умолчанию держите его выключенным.": "Never enable debug in production. Control the flag via an environment variable and keep it off by default.",
  "Используйте defusedxml: from defusedxml.ElementTree import parse. Он отключает опасные возможности XML.": "Use defusedxml: from defusedxml.ElementTree import parse. It disables the dangerous XML features.",
  "Для всего, что связано с безопасностью, используйте secrets: secrets.token_urlsafe(32), secrets.choice(...).": "For anything security-related use secrets: secrets.token_urlsafe(32), secrets.choice(...).",
  "Используйте tempfile.NamedTemporaryFile() или mkstemp() — они атомарно создают файл с безопасными правами.": "Use tempfile.NamedTemporaryFile() or mkstemp() — they atomically create the file with safe permissions.",
  "Включите autoescape=True. Для отдельных доверенных фрагментов используйте markupsafe.Markup явно и осознанно.": "Enable autoescape=True. For specific trusted fragments use markupsafe.Markup explicitly and deliberately.",
  "Заменяйте на явную проверку с исключением: if not user.is_admin: raise PermissionError(...).": "Replace with an explicit check that raises: if not user.is_admin: raise PermissionError(...).",
  "В продакшене DEBUG = False. Значение берите из переменной окружения, а ALLOWED_HOSTS задайте явно.": "In production, DEBUG = False. Take the value from an environment variable and set ALLOWED_HOSTS explicitly.",
  "Слушайте 127.0.0.1, если сервис нужен только локально. Наружу публикуйте через reverse-proxy с TLS и аутентификацией.": "Bind to 127.0.0.1 if the service is only needed locally. Expose it externally through a reverse proxy with TLS and authentication.",
  "Выдавайте минимально необходимые права: 0o600 для секретов, 0o644 для обычных файлов, 0o755 для каталогов.": "Grant the least necessary permissions: 0o600 for secrets, 0o644 for regular files, 0o755 for directories.",
  "Уберите eval(). Для JSON — JSON.parse(), для выбора поведения — объект-диспетчер или switch.": "Remove eval(). Use JSON.parse() for JSON, and a dispatch object or switch for choosing behavior.",
  "Замените на обычную функцию или таблицу обработчиков. Если нужен пользовательский сценарий — используйте песочницу с ограниченным DSL.": "Replace with a plain function or a handler table. If a user-defined scenario is needed, use a sandbox with a restricted DSL.",
  "Рендерите как текст: {value}. Если нужен HTML — прогоните через DOMPurify.sanitize(html) перед вставкой.": "Render as text: {value}. If HTML is needed, run it through DOMPurify.sanitize(html) before inserting.",
  "Используйте textContent для текста. Для HTML — DOMPurify.sanitize() или создание узлов через createElement.": "Use textContent for text. For HTML use DOMPurify.sanitize() or build nodes with createElement.",
  "Вставляйте узлы через insertAdjacentText или createElement, либо санитизируйте строку DOMPurify.": "Insert nodes via insertAdjacentText or createElement, or sanitize the string with DOMPurify.",
  "Стройте DOM через createElement/appendChild или используйте фреймворк. От document.write() стоит отказаться полностью.": "Build the DOM with createElement/appendChild or use a framework. document.write() should be abandoned entirely.",
  "Используйте execFile() или spawn() с массивом аргументов — они не запускают шелл: execFile(\"git\", [\"log\", branch]).": "Use execFile() or spawn() with an argument array — they do not launch a shell: execFile(\"git\", [\"log\", branch]).",
  "Уберите shell:true и передавайте аргументы массивом.": "Remove shell:true and pass arguments as an array.",
  "Передавайте значения плейсхолдерами: db.query(\"SELECT * FROM t WHERE id = ?\", [id]). В ORM пользуйтесь билдером, а не raw.": "Pass values as placeholders: db.query(\"SELECT * FROM t WHERE id = ?\", [id]). In an ORM use the builder, not raw.",
  "Используйте параметризованные запросы вместо конкатенации строк.": "Use parameterized queries instead of string concatenation.",
  "Удалите эту строку. Для самоподписанного сертификата добавьте свой CA через опцию ca или переменную NODE_EXTRA_CA_CERTS.": "Remove this line. For a self-signed certificate add your CA via the ca option or the NODE_EXTRA_CA_CERTS variable.",
  "Уберите опцию. Для внутреннего CA передайте его сертификат в поле ca.": "Remove the option. For an internal CA pass its certificate in the ca field.",
  "Всегда указывайте алгоритм явно: jwt.verify(token, key, { algorithms: [\"RS256\"] }).": "Always specify the algorithm explicitly: jwt.verify(token, key, { algorithms: [\"RS256\"] }).",
  "Для любых решений на основе токена используйте jwt.verify() с ключом и явным списком алгоритмов.": "For any token-based decision use jwt.verify() with a key and an explicit algorithm list.",
  "В браузере — crypto.getRandomValues(new Uint8Array(32)). В Node — crypto.randomBytes(32) или crypto.randomUUID().": "In the browser use crypto.getRandomValues(new Uint8Array(32)). In Node use crypto.randomBytes(32) or crypto.randomUUID().",
  "Используйте crypto.createCipheriv(\"aes-256-gcm\", key, iv) со случайным IV на каждое сообщение.": "Use crypto.createCipheriv(\"aes-256-gcm\", key, iv) with a random IV per message.",
  "Берите sha256 или sha512. Для паролей — bcrypt/argon2, а не «сырой» хеш.": "Use sha256 or sha512. For passwords use bcrypt/argon2, not a raw hash.",
  "Задайте белый список доменов. Origin \"*\" и credentials:true несовместимы — браузер отклонит такую комбинацию.": "Set an allowlist of domains. Origin \"*\" and credentials:true are incompatible — the browser rejects that combination.",
  "Передавайте конкретный origin: target.postMessage(data, \"https://app.example.com\"). На приёме проверяйте event.origin.": "Pass a specific origin: target.postMessage(data, \"https://app.example.com\"). On receipt, check event.origin.",
  "Редиректьте только на относительные пути или адреса из белого списка. Проверяйте, что URL начинается с \"/\" и не с \"//\".": "Redirect only to relative paths or allowlisted addresses. Check that the URL starts with \"/\" and not \"//\".",
  "Нормализуйте путь через path.resolve() и проверьте, что результат начинается с разрешённого каталога. Лучше — path.basename() для имени файла.": "Normalize the path with path.resolve() and check the result starts within an allowed directory. Better yet, use path.basename() for the file name.",
  "Передавайте функцию: setTimeout(() => doWork(), 100).": "Pass a function: setTimeout(() => doWork(), 100).",
  "Добавьте rel=\"noopener noreferrer\". Современные браузеры делают это сами, но старые — нет.": "Add rel=\"noopener noreferrer\". Modern browsers do this automatically, but older ones do not.",
  "Храните токен в cookie с HttpOnly, Secure и SameSite=Strict. Так его не прочитает JavaScript.": "Store the token in a cookie with HttpOnly, Secure and SameSite=Strict. Then JavaScript cannot read it.",
  "Ставьте { httpOnly: true, secure: true, sameSite: \"strict\" } для всех сессионных cookie.": "Set { httpOnly: true, secure: true, sameSite: \"strict\" } for all session cookies.",
  "Используйте JSON.parse(). Библиотеку node-serialize применять для недоверенных данных нельзя.": "Use JSON.parse(). The node-serialize library must not be used on untrusted data.",
  "Для недоверенного кода используйте отдельный процесс с ограничениями или изолированную среду (isolated-vm, WebAssembly).": "For untrusted code use a separate restricted process or an isolated environment (isolated-vm, WebAssembly).",
  "Упростите выражение, уберите вложенные квантификаторы. Ограничьте длину входа или используйте RE2-совместимый движок.": "Simplify the expression and remove nested quantifiers. Limit the input length or use an RE2-compatible engine.",
  "Проверьте, что инварианты действительно соблюдены, и опишите их в комментарии // SAFETY:. По возможности замените безопасным аналогом.": "Verify the invariants actually hold and document them in a // SAFETY: comment. Where possible, replace with a safe equivalent.",
  "Используйте безопасные преобразования: as для чисел, from_le_bytes для байтов, крейты bytemuck/zerocopy для POD-типов.": "Use safe conversions: as for numbers, from_le_bytes for bytes, and the bytemuck/zerocopy crates for POD types.",
  "Используйте std::str::from_utf8(bytes)? и обработайте ошибку, либо String::from_utf8_lossy() для «best effort».": "Use std::str::from_utf8(bytes)? and handle the error, or String::from_utf8_lossy() for a best-effort result.",
  "Используйте обычную индексацию или .get(i), который вернёт Option. Оптимизация оправдана только на измеренном горячем пути.": "Use normal indexing or .get(i), which returns an Option. The optimization is justified only on a measured hot path.",
  "Вызывайте программу напрямую: Command::new(\"git\").arg(\"log\").arg(&branch) — аргументы передаются как есть, без шелла.": "Call the program directly: Command::new(\"git\").arg(\"log\").arg(&branch) — arguments are passed as-is, without a shell.",
  "Уберите опцию. Для внутреннего CA добавьте корневой сертификат: .add_root_certificate(Certificate::from_pem(&pem)?).": "Remove the option. For an internal CA add the root certificate: .add_root_certificate(Certificate::from_pem(&pem)?).",
  "Используйте параметры драйвера: sqlx::query(\"SELECT * FROM t WHERE id = $1\").bind(id) или query! с проверкой на этапе компиляции.": "Use driver parameters: sqlx::query(\"SELECT * FROM t WHERE id = $1\").bind(id) or query! with compile-time checking.",
  "Используйте sha2::Sha256 или blake3. Для паролей — argon2 или bcrypt.": "Use sha2::Sha256 or blake3. For passwords use argon2 or bcrypt.",
  "Обработайте ошибку: ? с anyhow/thiserror, либо .unwrap_or_default() / .context(\"...\") с понятным сообщением.": "Handle the error: ? with anyhow/thiserror, or .unwrap_or_default() / .context(\"...\") with a clear message.",
  "Используйте checked_add/checked_mul и обрабатывайте None, либо saturating_/wrapping_ варианты, если поведение задумано.": "Use checked_add/checked_mul and handle None, or the saturating_/wrapping_ variants if the behavior is intended.",
  "Добавьте непривилегированного пользователя: RUN adduser -D app && USER app.": "Add an unprivileged user: RUN adduser -D app && USER app.",
  "Скачайте файл, проверьте контрольную сумму или подпись, и только потом запускайте.": "Download the file, verify a checksum or signature, and only then run it.",
  "Уберите флаг. Если мешает корпоративный CA, установите его сертификат в образ.": "Remove the flag. If a corporate CA is in the way, install its certificate into the image.",
  "Фиксируйте версию, а лучше digest: FROM node:22.13-alpine@sha256:...": "Pin the version, or better the digest: FROM node:22.13-alpine@sha256:...",
  "Избегайте eval. Используйте массивы аргументов и \"${var}\" в кавычках.": "Avoid eval. Use argument arrays and \"${var}\" in quotes.",
  "Используйте обычный pull_request. Если нужен именно pull_request_target — не делайте checkout кода из PR и не запускайте его сборку.": "Use a plain pull_request. If pull_request_target is truly needed, do not check out or build PR code.",
  "Фиксируйте action по полному SHA коммита: uses: actions/checkout@8f4b7f8... — тег можно оставить комментарием.": "Pin the action to a full commit SHA: uses: actions/checkout@8f4b7f8... — the tag can stay as a comment.",
  "Вызывайте программу напрямую: exec.Command(\"git\", \"log\", branch) — аргументы передаются как есть, без шелла.": "Call the program directly: exec.Command(\"git\", \"log\", branch) — arguments are passed as-is, without a shell.",
  "Используйте плейсхолдеры драйвера: db.Query(\"SELECT * FROM t WHERE id = $1\", id).": "Use driver placeholders: db.Query(\"SELECT * FROM t WHERE id = $1\", id).",
  "Уберите опцию. Для внутреннего CA добавьте его в RootCAs пула сертификатов.": "Remove the option. For an internal CA add it to the certificate pool's RootCAs.",
  "Используйте sha256.New(). Для паролей — golang.org/x/crypto/bcrypt или argon2.": "Use sha256.New(). For passwords use golang.org/x/crypto/bcrypt or argon2.",
  "Обработайте ошибку: if err != nil { return fmt.Errorf(\"...: %w\", err) }.": "Handle the error: if err != nil { return fmt.Errorf(\"...: %w\", err) }.",
  "Для всего, что связано с безопасностью, используйте crypto/rand.": "For anything security-related use crypto/rand.",
  "Используйте ProcessBuilder со списком аргументов и никогда не склеивайте команду из строк.": "Use ProcessBuilder with an argument list and never build the command from strings.",
  "Используйте PreparedStatement с параметрами: ps.setString(1, name).": "Use a PreparedStatement with parameters: ps.setString(1, name).",
  "Не десериализуйте недоверенные данные. Используйте JSON с явной схемой или ObjectInputFilter с белым списком классов.": "Do not deserialize untrusted data. Use JSON with an explicit schema or an ObjectInputFilter with a class allowlist.",
  "Отключите внешние сущности: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true).": "Disable external entities: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true).",
  "Берите MessageDigest.getInstance(\"SHA-256\"). Для паролей — BCrypt или Argon2.": "Use MessageDigest.getInstance(\"SHA-256\"). For passwords use BCrypt or Argon2.",
  "Используйте AES/GCM/NoPadding со случайным IV на каждое сообщение.": "Use AES/GCM/NoPadding with a random IV per message.",
  "Уберите eval(). Для данных используйте json_decode(), для выбора поведения — массив-диспетчер.": "Remove eval(). Use json_decode() for data and a dispatch array for choosing behavior.",
  "Экранируйте аргументы через escapeshellarg(), а лучше избегайте вызова внешних команд.": "Escape arguments with escapeshellarg(), or better, avoid calling external commands.",
  "Используйте подготовленные запросы PDO: $stmt = $pdo->prepare(\"SELECT * FROM t WHERE id = ?\"); $stmt->execute([$id]).": "Use PDO prepared statements: $stmt = $pdo->prepare(\"SELECT * FROM t WHERE id = ?\"); $stmt->execute([$id]).",
  "Используйте json_decode(). Если unserialize() необходим — ограничьте классы: unserialize($data, ['allowed_classes' => false]).": "Use json_decode(). If unserialize() is required, restrict classes: unserialize($data, ['allowed_classes' => false]).",
  "Подключайте только пути из белого списка. Никогда не передавайте пользовательский ввод в include.": "Include only allowlisted paths. Never pass user input to include.",
  "Передавайте аргументы массивом: system(\"git\", \"log\", branch) — так шелл не участвует.": "Pass arguments as an array: system(\"git\", \"log\", branch) — this avoids the shell.",
  "Передавайте параметры отдельно: where(\"id = ?\", id) или where(id: id).": "Pass parameters separately: where(\"id = ?\", id) or where(id: id).",
  "Используйте YAML.safe_load(data). Marshal на недоверенных данных применять нельзя.": "Use YAML.safe_load(data). Marshal must not be used on untrusted data.",
  "Используйте параметры: cmd.Parameters.AddWithValue(\"@id\", id).": "Use parameters: cmd.Parameters.AddWithValue(\"@id\", id).",
  "Перейдите на System.Text.Json или protobuf. BinaryFormatter применять нельзя.": "Switch to System.Text.Json or protobuf. BinaryFormatter must not be used.",
  "Уберите колбэк. Для внутреннего CA установите его сертификат в хранилище доверия.": "Remove the callback. For an internal CA install its certificate into the trust store.",
  "Используйте strncpy/strncat/snprintf с явным размером, а лучше std::string в C++. gets() удалён из стандарта C11.": "Use strncpy/strncat/snprintf with an explicit size, or better std::string in C++. gets() was removed from the C11 standard.",
  "Всегда указывайте формат явно: printf(\"%s\", user_input).": "Always specify the format explicitly: printf(\"%s\", user_input).",
  "Используйте execve() с массивом аргументов вместо system().": "Use execve() with an argument array instead of system().",
  "Ограничьте cidr_blocks конкретными подсетями. Для админ-доступа используйте VPN или bastion.": "Restrict cidr_blocks to specific subnets. For admin access use a VPN or a bastion.",
  "Используйте private ACL и выдавайте доступ через presigned URL или CloudFront с OAI.": "Use a private ACL and grant access via presigned URLs or CloudFront with OAI.",
  "Включите шифрование: encrypted = true, а для управляемых ключей укажите kms_key_id.": "Enable encryption: encrypted = true, and for managed keys set kms_key_id.",
  "Используйте переменные с sensitive = true и подставляйте значения из Vault, AWS Secrets Manager или переменных окружения.": "Use variables with sensitive = true and pull values from Vault, AWS Secrets Manager, or environment variables.",
  "Уберите privileged. Если нужны отдельные возможности — выдайте их точечно через capabilities.add.": "Remove privileged. If specific capabilities are needed, grant them individually via capabilities.add.",
  "Задайте allowPrivilegeEscalation: false в securityContext.": "Set allowPrivilegeEscalation: false in the securityContext.",
  "Используйте PersistentVolume или emptyDir. hostPath оправдан только для системных DaemonSet.": "Use a PersistentVolume or emptyDir. hostPath is justified only for system DaemonSets.",
  "Задайте runAsNonRoot: true и конкретный runAsUser.": "Set runAsNonRoot: true and a specific runAsUser.",
  "Уберите Invoke-Expression. Вызывайте команды напрямую с параметрами через splatting.": "Remove Invoke-Expression. Call commands directly with parameters via splatting.",
  "Уберите флаг. Для внутреннего CA установите его сертификат в хранилище доверенных.": "Remove the flag. For an internal CA install its certificate into the trusted store.",
  "Идентификатор ключа AWS зашит в исходник. В паре с секретным ключом он даёт полный доступ к аккаунту AWS в рамках прав этого ключа.": "An AWS key id is hardcoded in the source. Paired with the secret key it grants full access to the AWS account within that key's permissions.",
  "Секретный ключ AWS в исходнике. Вместе с Access Key ID позволяет управлять инфраструктурой и данными аккаунта.": "An AWS secret key is in the source. Together with the Access Key ID it allows managing the account's infrastructure and data.",
  "Токен GitHub даёт доступ к репозиториям владельца в объёме своих scope: чтение приватного кода, пуш, а иногда управление организацией.": "A GitHub token grants access to the owner's repositories within its scopes: reading private code, pushing, and sometimes managing the organization.",
  "В файле лежит приватный ключ (RSA/EC/OpenSSH/PGP). Он позволяет расшифровать трафик, подделать подпись или зайти на сервер по SSH.": "The file contains a private key (RSA/EC/OpenSSH/PGP). It can decrypt traffic, forge a signature, or log into a server over SSH.",
  "Токен Slack позволяет читать историю каналов и отправлять сообщения от имени бота или пользователя.": "A Slack token can read channel history and send messages as the bot or user.",
  "Живой секретный ключ Stripe даёт доступ к платёжным операциям и данным клиентов.": "A live Stripe secret key grants access to payment operations and customer data.",
  "Ключ Google API в коде. Без ограничений по домену/IP им может воспользоваться кто угодно — вплоть до исчерпания вашей квоты и счёта.": "A Google API key in code. Without domain/IP restrictions anyone can use it — up to draining your quota and your bill.",
  "URI содержит логин и пароль к базе данных. Если сервис доступен по сети, это прямой путь к данным.": "The URI contains a database login and password. If the service is reachable over the network, this is a direct path to the data.",
  "Токен даёт полный контроль над ботом: чтение сообщений и отправка от его имени.": "The token grants full control of the bot: reading messages and sending as it.",
  "Ключ доступа к платному LLM-API. Утечка означает списания с вашего счёта и доступ к вашим данным в сервисе.": "An access key to a paid LLM API. A leak means charges on your account and access to your data in the service.",
  "Пароль в исходнике виден всем, у кого есть доступ к репозиторию, и остаётся в истории git даже после удаления строки.": "A password in the source is visible to everyone with repo access and remains in git history even after the line is deleted.",
  "Значение выглядит как реальный ключ доступа: достаточно длинное и с высокой энтропией.": "The value looks like a real access key: long enough and high in entropy.",
  "В исходнике лежит готовый JWT. Если он ещё не истёк, им можно воспользоваться напрямую; заодно он раскрывает структуру ваших claim'ов.": "A ready JWT is in the source. If it has not expired it can be used directly; it also reveals the structure of your claims.",
  "Немедленно отзовите ключ в IAM — он скомпрометирован фактом попадания в репозиторий. Используйте IAM-роли или переменные окружения. Историю git тоже нужно вычистить (git filter-repo).": "Revoke the key in IAM immediately — landing in the repository compromises it. Use IAM roles or environment variables. The git history must be scrubbed too (git filter-repo).",
  "Отзовите ключ в IAM прямо сейчас. Перейдите на IAM-роли (для EC2/ECS/Lambda) или на временные учётные данные STS.": "Revoke the key in IAM right now. Switch to IAM roles (for EC2/ECS/Lambda) or temporary STS credentials.",
  "Отзовите токен в Settings → Developer settings → Personal access tokens. Для CI используйте GITHUB_TOKEN или GitHub App с минимальными правами.": "Revoke the token in Settings → Developer settings → Personal access tokens. For CI use GITHUB_TOKEN or a GitHub App with minimal permissions.",
  "Считайте ключ скомпрометированным: сгенерируйте новый и отзовите старый. Приватные ключи не хранят в репозитории — используйте секрет-хранилище (Vault, KMS, SOPS).": "Treat the key as compromised: generate a new one and revoke the old. Private keys do not belong in a repository — use a secret store (Vault, KMS, SOPS).",
  "Отзовите токен в настройках приложения Slack и выпустите новый. Храните его в переменных окружения.": "Revoke the token in the Slack app settings and issue a new one. Store it in environment variables.",
  "Отзовите ключ в дашборде Stripe (Developers → API keys) и выпустите новый. Секретный ключ должен быть только на сервере.": "Revoke the key in the Stripe dashboard (Developers → API keys) and issue a new one. The secret key must live only on the server.",
  "Отзовите ключ в Google Cloud Console и выпустите новый с ограничениями по HTTP-referrer или IP.": "Revoke the key in the Google Cloud Console and issue a new one restricted by HTTP referrer or IP.",
  "Вынесите строку подключения в переменную окружения. Пароль в репозитории считайте скомпрометированным и смените.": "Move the connection string to an environment variable. Treat the password in the repository as compromised and change it.",
  "Отзовите токен через @BotFather (/revoke) и получите новый. Храните в переменной окружения.": "Revoke the token via @BotFather (/revoke) and get a new one. Store it in an environment variable.",
  "Отзовите ключ в кабинете провайдера и выпустите новый. Ключ должен жить в переменной окружения на сервере, а не в клиентском коде.": "Revoke the key in the provider's console and issue a new one. The key must live in a server-side environment variable, not in client code.",
  "Вынесите в переменную окружения или секрет-хранилище. Смените сам пароль — он уже скомпрометирован.": "Move it to an environment variable or a secret store. Change the password itself — it is already compromised.",
  "Перенесите в переменную окружения или секрет-хранилище и отзовите текущее значение.": "Move it to an environment variable or a secret store and revoke the current value.",
  "Уберите токен из кода. Если он рабочий — отзовите и смените ключ подписи.": "Remove the token from the code. If it is live, revoke it and rotate the signing key.",

  // -- language
  Язык: "Language",
  Русский: "Русский",
  "English (английский)": "English",
};
