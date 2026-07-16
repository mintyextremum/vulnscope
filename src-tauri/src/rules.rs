use crate::model::{Confidence, Language, Severity};
use once_cell::sync::Lazy;
use regex::{Regex, RegexSet};
use std::collections::HashMap;

/// A single detection rule. Patterns use the `regex` crate, which has no
/// lookaround — "match X unless Y" is expressed with `unless_contains` instead.
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: &'static str,
    pub languages: &'static [Language],
    pub pattern: &'static str,
    /// Drop the match if the matched text contains any of these (case-insensitive).
    pub unless_contains: &'static [&'static str],
    pub cwe: &'static [&'static str],
    pub owasp: Option<&'static str>,
    pub references: &'static [&'static str],
    /// Rules that are noisy in test code and safe to suppress there.
    pub skip_in_tests: bool,
}

const JS_FAMILY: &[Language] = &[
    Language::JavaScript,
    Language::TypeScript,
    Language::Jsx,
    Language::Tsx,
];
const PY: &[Language] = &[Language::Python];
const RS: &[Language] = &[Language::Rust];

const OWASP_INJECTION: &str = "A03:2021 – Injection";
const OWASP_CRYPTO: &str = "A02:2021 – Cryptographic Failures";
const OWASP_MISCONFIG: &str = "A05:2021 – Security Misconfiguration";
const OWASP_ACCESS: &str = "A01:2021 – Broken Access Control";
const OWASP_INTEGRITY: &str = "A08:2021 – Software and Data Integrity Failures";
const OWASP_AUTH: &str = "A07:2021 – Identification and Authentication Failures";
const OWASP_DESIGN: &str = "A04:2021 – Insecure Design";
const OWASP_VULN_COMP: &str = "A06:2021 – Vulnerable and Outdated Components";

pub static RULES: &[Rule] = &[
    // ---------------------------------------------------------------- Python
    Rule {
        id: "VS-PY-001",
        title: "Вызов eval() с динамическими данными",
        description: "eval() выполняет переданную строку как код Python. Если в неё попадают данные от пользователя, атакующий получает выполнение произвольного кода в процессе приложения.",
        recommendation: "Уберите eval(). Для разбора данных используйте json.loads(), для literal-структур — ast.literal_eval(), для диспетчеризации — словарь функций.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: PY,
        pattern: r"\beval\s*\(",
        unless_contains: &[],
        cwe: &["CWE-95", "CWE-94"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-002",
        title: "Вызов exec() с динамическими данными",
        description: "exec() исполняет произвольный код Python. Любое влияние пользователя на аргумент означает полную компрометацию процесса.",
        recommendation: "Замените exec() явной логикой: словарь-диспетчер, importlib для загрузки модулей из белого списка.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: PY,
        pattern: r"\bexec\s*\(",
        unless_contains: &[],
        cwe: &["CWE-95", "CWE-94"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-003",
        title: "subprocess с shell=True",
        description: "shell=True запускает команду через системный шелл, поэтому метасимволы (; | & $() ``) в аргументах интерпретируются. Подстановка пользовательских данных даёт инъекцию команд.",
        recommendation: "Уберите shell=True и передавайте команду списком аргументов: subprocess.run([\"ls\", \"-l\", path]). Тогда аргументы не парсятся шеллом.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Инъекция команд",
        languages: PY,
        pattern: r"shell\s*=\s*True",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-004",
        title: "os.system() — выполнение команды через шелл",
        description: "os.system() всегда идёт через шелл и не умеет экранировать аргументы. Это классический вектор инъекции команд.",
        recommendation: "Используйте subprocess.run([...]) со списком аргументов и без shell=True.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Инъекция команд",
        languages: PY,
        pattern: r"\bos\.system\s*\(",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-005",
        title: "os.popen() — выполнение команды через шелл",
        description: "os.popen() запускает строку в шелле. Пользовательский ввод в этой строке приводит к инъекции команд.",
        recommendation: "Перейдите на subprocess.run([...], capture_output=True) без shell=True.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Инъекция команд",
        languages: PY,
        pattern: r"\bos\.popen\s*\(",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-006",
        title: "Десериализация через pickle",
        description: "pickle.load()/loads() при разборе данных вызывает конструкторы объектов и может выполнить произвольный код. Формат не предназначен для недоверенных данных.",
        recommendation: "Для обмена данными используйте JSON. Если pickle необходим — принимайте его только из доверенного источника и подписывайте (HMAC).",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: PY,
        pattern: r"\b(?:pickle|cPickle|_pickle|dill|shelve)\.loads?\s*\(",
        unless_contains: &[],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://docs.python.org/3/library/pickle.html#module-pickle"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-007",
        title: "yaml.load() без безопасного загрузчика",
        description: "Загрузчик по умолчанию в PyYAML умеет конструировать произвольные объекты Python, что даёт выполнение кода при разборе недоверенного YAML.",
        recommendation: "Используйте yaml.safe_load(data) или явно yaml.load(data, Loader=yaml.SafeLoader).",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: PY,
        pattern: r"yaml\.load\s*\([^)]*\)",
        unless_contains: &["SafeLoader", "BaseLoader", "safe_load"],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://pyyaml.org/wiki/PyYAMLDocumentation"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-008",
        title: "SQL-запрос собирается f-строкой",
        description: "Подстановка значений в текст SQL через f-строку не экранирует кавычки и спецсимволы. Пользовательский ввод может изменить структуру запроса — это SQL-инъекция.",
        recommendation: "Используйте параметризованные запросы: cursor.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,)). Драйвер сам выполнит экранирование.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "SQL-инъекция",
        languages: PY,
        pattern: r#"(?i)\.execute(?:many|script)?\s*\(\s*f["']"#,
        unless_contains: &[],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-009",
        title: "SQL-запрос собирается конкатенацией или %-форматированием",
        description: "Склейка пользовательских данных с текстом SQL через + или % позволяет атакующему дописать собственные конструкции в запрос.",
        recommendation: "Передавайте значения отдельным параметром: cursor.execute(query, params). Никогда не форматируйте SQL строками.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "SQL-инъекция",
        languages: PY,
        pattern: r#"(?i)\.execute(?:many|script)?\s*\(\s*["'][^"']*(?:select|insert|update|delete|drop)[^"']*["']\s*(?:%|\+|\.format)"#,
        unless_contains: &[],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-010",
        title: "Слабый хеш (MD5/SHA-1)",
        description: "MD5 и SHA-1 уязвимы к коллизиям и не годятся для подписей, проверки целостности и хранения паролей.",
        recommendation: "Для целостности берите hashlib.sha256. Для паролей — bcrypt, scrypt или argon2 (passlib/argon2-cffi), никогда не «сырой» хеш. Если хеш используется не для безопасности, добавьте usedforsecurity=False.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Криптография",
        languages: PY,
        pattern: r"hashlib\.(?:md5|sha1)\s*\(",
        unless_contains: &["usedforsecurity=False"],
        cwe: &["CWE-327", "CWE-328"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-011",
        title: "Отключена проверка TLS-сертификата",
        description: "verify=False заставляет requests принимать любой сертификат. Соединение перестаёт защищать от man-in-the-middle: трафик можно прочитать и подменить.",
        recommendation: "Уберите verify=False. Для внутреннего CA укажите путь к его сертификату: requests.get(url, verify=\"/path/ca.pem\").",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: PY,
        pattern: r"verify\s*=\s*False",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-012",
        title: "Отключена проверка hostname в ssl",
        description: "check_hostname=False или CERT_NONE снимает проверку того, что сертификат выдан именно тому хосту, к которому идёт подключение.",
        recommendation: "Оставьте контекст по умолчанию: ssl.create_default_context(). Он включает и проверку цепочки, и проверку hostname.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: PY,
        pattern: r"check_hostname\s*=\s*False|CERT_NONE|_create_unverified_context",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-013",
        title: "Flask запущен с debug=True",
        description: "Debug-режим Flask включает интерактивную консоль Werkzeug. На доступном извне хосте это прямое выполнение кода без аутентификации.",
        recommendation: "Никогда не включайте debug в продакшене. Управляйте флагом через переменную окружения и по умолчанию держите его выключенным.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: PY,
        pattern: r"debug\s*=\s*True",
        unless_contains: &[],
        cwe: &["CWE-489"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/489.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-014",
        title: "Разбор XML уязвим к XXE и bomb-атакам",
        description: "Стандартные парсеры xml.etree, minidom и lxml по умолчанию могут раскрывать внешние сущности — это чтение локальных файлов и SSRF, а также exponential entity expansion.",
        recommendation: "Используйте defusedxml: from defusedxml.ElementTree import parse. Он отключает опасные возможности XML.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "XXE",
        languages: PY,
        pattern: r"(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)\.(?:parse|fromstring|parseString)\s*\(",
        unless_contains: &["defusedxml"],
        cwe: &["CWE-611"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/611.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-015",
        title: "Слабый генератор случайных чисел для секретов",
        description: "Модуль random — предсказуемый PRNG (Mersenne Twister). Токены, пароли и ключи, полученные из него, восстанавливаются по нескольким выданным значениям.",
        recommendation: "Для всего, что связано с безопасностью, используйте secrets: secrets.token_urlsafe(32), secrets.choice(...).",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "Криптография",
        languages: PY,
        pattern: r"random\.(?:random|randint|choice|randrange|sample|shuffle|getrandbits)\s*\(",
        unless_contains: &[],
        cwe: &["CWE-338", "CWE-330"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://docs.python.org/3/library/secrets.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-016",
        title: "tempfile.mktemp() — гонка при создании файла",
        description: "mktemp() только возвращает имя, не создавая файл. Между проверкой и созданием другой процесс может подставить симлинк (TOCTOU).",
        recommendation: "Используйте tempfile.NamedTemporaryFile() или mkstemp() — они атомарно создают файл с безопасными правами.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Работа с файлами",
        languages: PY,
        pattern: r"tempfile\.mktemp\s*\(",
        unless_contains: &[],
        cwe: &["CWE-377", "CWE-367"],
        owasp: Some(OWASP_DESIGN),
        references: &["https://cwe.mitre.org/data/definitions/377.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-017",
        title: "Jinja2 с отключённым автоэкранированием",
        description: "autoescape=False означает, что переменные вставляются в HTML как есть. Любые пользовательские данные в шаблоне становятся XSS.",
        recommendation: "Включите autoescape=True. Для отдельных доверенных фрагментов используйте markupsafe.Markup явно и осознанно.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "XSS",
        languages: PY,
        pattern: r"autoescape\s*=\s*False",
        unless_contains: &[],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-018",
        title: "assert используется для контроля доступа",
        description: "Интерпретатор с флагом -O полностью удаляет assert. Если на нём держится проверка прав, в оптимизированной сборке она просто исчезнет.",
        recommendation: "Заменяйте на явную проверку с исключением: if not user.is_admin: raise PermissionError(...).",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "Контроль доступа",
        languages: PY,
        pattern: r"assert\s+.*(?:is_admin|is_authenticated|has_perm|is_staff|is_superuser|authorized)",
        unless_contains: &[],
        cwe: &["CWE-617", "CWE-285"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/617.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-019",
        title: "Django запущен с DEBUG = True",
        description: "При DEBUG=True Django на любой ошибке отдаёт трейсбек с фрагментами кода, настройками и значениями переменных окружения.",
        recommendation: "В продакшене DEBUG = False. Значение берите из переменной окружения, а ALLOWED_HOSTS задайте явно.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: PY,
        pattern: r"(?m)^\s*DEBUG\s*=\s*True",
        unless_contains: &[],
        cwe: &["CWE-489", "CWE-215"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.djangoproject.com/en/stable/ref/settings/#debug"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-020",
        title: "Привязка сервера ко всем интерфейсам",
        description: "0.0.0.0 открывает порт на всех сетевых интерфейсах, включая внешние. Часто это делают для отладки и забывают вернуть обратно.",
        recommendation: "Слушайте 127.0.0.1, если сервис нужен только локально. Наружу публикуйте через reverse-proxy с TLS и аутентификацией.",
        severity: Severity::Low,
        confidence: Confidence::Low,
        category: "Конфигурация",
        languages: PY,
        pattern: r#"(?:host\s*=\s*|bind\s*\(\s*\(\s*)["']0\.0\.0\.0["']"#,
        unless_contains: &[],
        cwe: &["CWE-1327"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/1327.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-021",
        title: "Права 0777 на файл или каталог",
        description: "chmod 0777 даёт запись любому локальному пользователю. Исполняемый файл или скрипт с такими правами можно подменить.",
        recommendation: "Выдавайте минимально необходимые права: 0o600 для секретов, 0o644 для обычных файлов, 0o755 для каталогов.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Работа с файлами",
        languages: PY,
        pattern: r"chmod\s*\([^)]*0o?777",
        unless_contains: &[],
        cwe: &["CWE-732"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/732.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-022",
        title: "extractall() — распаковка без проверки путей",
        description: "tarfile.extractall и zipfile.extractall доверяют путям внутри архива. Запись вида ../../etc даёт запись за пределы целевого каталога (Zip Slip).",
        recommendation: "Проверяйте каждый путь перед распаковкой или используйте tarfile с filter=\"data\" (Python 3.12+), отсекающим выходы за каталог.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Path traversal",
        languages: PY,
        pattern: r"\.extractall\s*\(",
        unless_contains: &["filter="],
        cwe: &["CWE-22"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/22.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-023",
        title: "SSTI: render_template_string с данными",
        description: "render_template_string компилирует переданную строку как шаблон Jinja2. Пользовательский ввод в ней приводит к инъекции шаблона и выполнению кода на сервере.",
        recommendation: "Рендерите статические шаблоны из файлов и передавайте данные через контекст, а не собирайте текст шаблона из ввода.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: PY,
        pattern: r"render_template_string\s*\(",
        unless_contains: &[],
        cwe: &["CWE-94"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/94.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-024",
        title: "JWT: проверка подписи отключена",
        description: "verify=False или verify_signature: False заставляет jwt.decode принять токен без проверки подписи. Атакующий сможет подделать любые claims.",
        recommendation: "Всегда проверяйте подпись: jwt.decode(token, key, algorithms=[\"RS256\"]). Не отключайте verify_signature.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Аутентификация",
        languages: PY,
        pattern: r#"(?i)verify_signature["']?\s*:\s*False|jwt\.decode\s*\([^)]*\bverify\s*=\s*False"#,
        unless_contains: &[],
        cwe: &["CWE-347"],
        owasp: Some(OWASP_AUTH),
        references: &["https://cwe.mitre.org/data/definitions/347.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-025",
        title: "mark_safe отключает экранирование (XSS)",
        description: "mark_safe помечает строку как безопасный HTML, и Django вставляет её в шаблон без экранирования. Пользовательский ввод в ней даёт XSS.",
        recommendation: "Не вызывайте mark_safe на пользовательских данных. Для нужной разметки используйте bleach.clean с белым списком тегов.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "XSS",
        languages: PY,
        pattern: r"\bmark_safe\s*\(",
        unless_contains: &[],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-026",
        title: "SSH: проверка ключа хоста отключена (paramiko)",
        description: "AutoAddPolicy и WarningPolicy принимают ключ хоста автоматически. Соединение перестаёт защищать от man-in-the-middle.",
        recommendation: "Используйте RejectPolicy и заранее загруженные known_hosts через load_system_host_keys.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: PY,
        pattern: r"(?:AutoAddPolicy|WarningPolicy)\b",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },

    // ------------------------------------------------------ JavaScript / TS
    Rule {
        id: "VS-JS-001",
        title: "Вызов eval()",
        description: "eval() исполняет строку как JavaScript в текущей области видимости. С данными от пользователя это выполнение произвольного кода и кража сессии.",
        recommendation: "Уберите eval(). Для JSON — JSON.parse(), для выбора поведения — объект-диспетчер или switch.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: JS_FAMILY,
        pattern: r"\beval\s*\(",
        unless_contains: &[],
        cwe: &["CWE-95", "CWE-94"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-JS-002",
        title: "Конструктор Function() из строки",
        description: "new Function(str) компилирует строку в функцию — это тот же eval, только через другой вход, и он так же обходится CSP-политикой без unsafe-eval.",
        recommendation: "Замените на обычную функцию или таблицу обработчиков. Если нужен пользовательский сценарий — используйте песочницу с ограниченным DSL.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: JS_FAMILY,
        pattern: r"new\s+Function\s*\(",
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-JS-003",
        title: "React: dangerouslySetInnerHTML",
        description: "Этот проп отключает экранирование React и вставляет HTML как есть. Если строка содержит пользовательские данные, это XSS.",
        recommendation: "Рендерите как текст: {value}. Если нужен HTML — прогоните через DOMPurify.sanitize(html) перед вставкой.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "XSS",
        languages: JS_FAMILY,
        pattern: r"dangerouslySetInnerHTML",
        unless_contains: &["DOMPurify", "sanitize"],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-004",
        title: "Присваивание в innerHTML / outerHTML",
        description: "innerHTML парсит строку как HTML. Пользовательские данные в ней приводят к XSS: скрипт исполнится в контексте вашего домена.",
        recommendation: "Используйте textContent для текста. Для HTML — DOMPurify.sanitize() или создание узлов через createElement.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "XSS",
        languages: JS_FAMILY,
        pattern: r"\.(?:inner|outer)HTML\s*(?:\+)?=",
        unless_contains: &["DOMPurify", "sanitize", r#"= ""#, "= ''"],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-005",
        title: "insertAdjacentHTML с динамическими данными",
        description: "Метод вставляет строку как разметку, минуя экранирование. Тот же вектор XSS, что и innerHTML.",
        recommendation: "Вставляйте узлы через insertAdjacentText или createElement, либо санитизируйте строку DOMPurify.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "XSS",
        languages: JS_FAMILY,
        pattern: r"\.insertAdjacentHTML\s*\(",
        unless_contains: &["DOMPurify", "sanitize"],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-006",
        title: "document.write()",
        description: "document.write() пишет строку прямо в поток документа как HTML. Это и XSS-вектор, и причина блокировки парсера.",
        recommendation: "Стройте DOM через createElement/appendChild или используйте фреймворк. От document.write() стоит отказаться полностью.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "XSS",
        languages: JS_FAMILY,
        pattern: r"document\.write(?:ln)?\s*\(",
        unless_contains: &[],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-007",
        title: "child_process.exec() — команда через шелл",
        description: "exec() передаёт строку системному шеллу целиком. Пользовательские данные в команде дают инъекцию: `; rm -rf /` отработает.",
        recommendation: "Используйте execFile() или spawn() с массивом аргументов — они не запускают шелл: execFile(\"git\", [\"log\", branch]).",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Инъекция команд",
        languages: JS_FAMILY,
        pattern: r"(?:child_process\.)?exec(?:Sync)?\s*\(\s*[`\x22']",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-008",
        title: "spawn/execFile с shell: true",
        description: "Опция shell:true возвращает разбор аргументов шеллу и сводит на нет главное преимущество spawn перед exec.",
        recommendation: "Уберите shell:true и передавайте аргументы массивом.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Инъекция команд",
        languages: JS_FAMILY,
        pattern: r"shell\s*:\s*true",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-009",
        title: "SQL-запрос собирается шаблонной строкой",
        description: "Интерполяция ${...} в тексте SQL не экранирует кавычки. Пользовательский ввод меняет структуру запроса — SQL-инъекция.",
        recommendation: "Передавайте значения плейсхолдерами: db.query(\"SELECT * FROM t WHERE id = ?\", [id]). В ORM пользуйтесь билдером, а не raw.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "SQL-инъекция",
        languages: JS_FAMILY,
        pattern: r"(?i)(?:query|execute|raw)\s*\(\s*`[^`]*(?:select|insert|update|delete|drop)[^`]*\$\{",
        unless_contains: &[],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-010",
        title: "SQL-запрос собирается конкатенацией",
        description: "Склейка SQL со значениями через + позволяет атакующему дописать в запрос свои условия или подзапросы.",
        recommendation: "Используйте параметризованные запросы вместо конкатенации строк.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "SQL-инъекция",
        languages: JS_FAMILY,
        pattern: r#"(?i)(?:query|execute|raw)\s*\(\s*["'][^"']*(?:select|insert|update|delete|drop)[^"']*["']\s*\+"#,
        unless_contains: &[],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-011",
        title: "Отключена проверка TLS через NODE_TLS_REJECT_UNAUTHORIZED",
        description: "Значение 0 глобально отключает проверку сертификатов для всего процесса Node. Все исходящие HTTPS-соединения становятся уязвимы к MITM.",
        recommendation: "Удалите эту строку. Для самоподписанного сертификата добавьте свой CA через опцию ca или переменную NODE_EXTRA_CA_CERTS.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: JS_FAMILY,
        pattern: r#"NODE_TLS_REJECT_UNAUTHORIZED["']?\s*\]?\s*=\s*["']?0"#,
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-012",
        title: "rejectUnauthorized: false",
        description: "Опция отключает проверку цепочки сертификатов для конкретного соединения — трафик можно перехватить и подменить.",
        recommendation: "Уберите опцию. Для внутреннего CA передайте его сертификат в поле ca.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: JS_FAMILY,
        pattern: r"rejectUnauthorized\s*:\s*false",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-013",
        title: "JWT: разрешён алгоритм none или не задан список алгоритмов",
        description: "Алгоритм none означает подпись без ключа — токен можно подделать целиком. Отсутствие явного списка алгоритмов открывает атаку смены алгоритма (RS256 → HS256).",
        recommendation: "Всегда указывайте алгоритм явно: jwt.verify(token, key, { algorithms: [\"RS256\"] }).",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Аутентификация",
        languages: JS_FAMILY,
        pattern: r#"(?i)algorithms?\s*:\s*\[?\s*["']none["']"#,
        unless_contains: &[],
        cwe: &["CWE-347"],
        owasp: Some(OWASP_AUTH),
        references: &["https://cwe.mitre.org/data/definitions/347.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-014",
        title: "jwt.decode() вместо jwt.verify()",
        description: "decode() читает содержимое токена, но не проверяет подпись. Доверять таким данным нельзя — их может подделать кто угодно.",
        recommendation: "Для любых решений на основе токена используйте jwt.verify() с ключом и явным списком алгоритмов.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Аутентификация",
        languages: JS_FAMILY,
        pattern: r"jwt\.decode\s*\(",
        unless_contains: &[],
        cwe: &["CWE-347"],
        owasp: Some(OWASP_AUTH),
        references: &["https://cwe.mitre.org/data/definitions/347.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-015",
        title: "Math.random() для токена или идентификатора сессии",
        description: "Math.random() не криптостойкий: состояние генератора восстанавливается по нескольким значениям, а значит токены предсказуемы.",
        recommendation: "В браузере — crypto.getRandomValues(new Uint8Array(32)). В Node — crypto.randomBytes(32) или crypto.randomUUID().",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "Криптография",
        languages: JS_FAMILY,
        pattern: r"Math\.random\s*\(\s*\)",
        unless_contains: &[],
        cwe: &["CWE-338", "CWE-330"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/338.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-JS-016",
        title: "Устаревший crypto.createCipher()",
        description: "createCipher() выводит ключ из пароля слабой схемой и работает без IV, что даёт повторяющийся шифротекст для одинаковых данных.",
        recommendation: "Используйте crypto.createCipheriv(\"aes-256-gcm\", key, iv) со случайным IV на каждое сообщение.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Криптография",
        languages: JS_FAMILY,
        pattern: r"crypto\.create(?:Cipher|Decipher)\s*\(",
        unless_contains: &["createCipheriv", "createDecipheriv"],
        cwe: &["CWE-327"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://nodejs.org/api/crypto.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-017",
        title: "Слабый хеш (MD5/SHA-1) в crypto",
        description: "MD5 и SHA-1 подвержены коллизиям, их нельзя применять для подписей и проверки целостности.",
        recommendation: "Берите sha256 или sha512. Для паролей — bcrypt/argon2, а не «сырой» хеш.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Криптография",
        languages: JS_FAMILY,
        pattern: r#"createHash\s*\(\s*["'](?:md5|sha1)["']"#,
        unless_contains: &[],
        cwe: &["CWE-327", "CWE-328"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-JS-018",
        title: "CORS: разрешены все источники",
        description: "origin \"*\" разрешает любому сайту читать ответы вашего API. В связке с credentials:true это позволяет чужой странице действовать от имени залогиненного пользователя.",
        recommendation: "Задайте белый список доменов. Origin \"*\" и credentials:true несовместимы — браузер отклонит такую комбинацию.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: JS_FAMILY,
        pattern: r#"(?i)origin\s*:\s*["']\*["']"#,
        unless_contains: &[],
        cwe: &["CWE-942", "CWE-346"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/942.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-019",
        title: "postMessage с целевым источником *",
        description: "Указание \"*\" отправляет сообщение любому окну, которое сейчас загружено во фрейм. Если там чужой сайт, он прочитает данные.",
        recommendation: "Передавайте конкретный origin: target.postMessage(data, \"https://app.example.com\"). На приёме проверяйте event.origin.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Утечка данных",
        languages: JS_FAMILY,
        pattern: r#"postMessage\s*\([^)]*,\s*["']\*["']"#,
        unless_contains: &[],
        cwe: &["CWE-346"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/346.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-020",
        title: "Открытый редирект из пользовательских данных",
        description: "Редирект по адресу из запроса позволяет увести пользователя на фишинговый сайт по ссылке с вашего домена.",
        recommendation: "Редиректьте только на относительные пути или адреса из белого списка. Проверяйте, что URL начинается с \"/\" и не с \"//\".",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Открытый редирект",
        languages: JS_FAMILY,
        pattern: r"res\.redirect\s*\(\s*req\.(?:query|params|body)",
        unless_contains: &[],
        cwe: &["CWE-601"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/601.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-021",
        title: "Path traversal: путь из пользовательских данных",
        description: "Склейка пути с данными запроса позволяет выйти за пределы каталога через ../ и прочитать произвольные файлы.",
        recommendation: "Нормализуйте путь через path.resolve() и проверьте, что результат начинается с разрешённого каталога. Лучше — path.basename() для имени файла.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Path traversal",
        languages: JS_FAMILY,
        pattern: r"(?:readFile|readFileSync|createReadStream|sendFile|writeFile|writeFileSync|unlink)\s*\([^)]*req\.(?:query|params|body)",
        unless_contains: &["basename", "resolve"],
        cwe: &["CWE-22"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/22.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-022",
        title: "setTimeout/setInterval со строкой вместо функции",
        description: "Если первым аргументом передана строка, она исполняется как код — это скрытый eval.",
        recommendation: "Передавайте функцию: setTimeout(() => doWork(), 100).",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Выполнение кода",
        languages: JS_FAMILY,
        pattern: r#"set(?:Timeout|Interval)\s*\(\s*["'`]"#,
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-023",
        title: "target=\"_blank\" без rel=\"noopener\"",
        description: "Открытая вкладка получает доступ к window.opener и может подменить исходную страницу на фишинговую (reverse tabnabbing).",
        recommendation: "Добавьте rel=\"noopener noreferrer\". Современные браузеры делают это сами, но старые — нет.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: JS_FAMILY,
        pattern: r#"target\s*=\s*["'{]?_blank"#,
        unless_contains: &["noopener", "noreferrer"],
        cwe: &["CWE-1022"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/1022.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-024",
        title: "Токен хранится в localStorage",
        description: "localStorage доступен любому скрипту на странице. Одна XSS — и токен утёк. В отличие от cookie, флаг HttpOnly здесь недоступен.",
        recommendation: "Храните токен в cookie с HttpOnly, Secure и SameSite=Strict. Так его не прочитает JavaScript.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "Хранение секретов",
        languages: JS_FAMILY,
        pattern: r#"localStorage\.setItem\s*\(\s*["'][^"']*(?:token|jwt|auth|secret|password|session|apikey|api_key)"#,
        unless_contains: &[],
        cwe: &["CWE-522", "CWE-922"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/922.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-025",
        title: "Cookie без флагов httpOnly / secure",
        description: "Без httpOnly cookie читается скриптом при XSS, без secure — уходит по открытому HTTP и перехватывается в сети.",
        recommendation: "Ставьте { httpOnly: true, secure: true, sameSite: \"strict\" } для всех сессионных cookie.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "Конфигурация",
        languages: JS_FAMILY,
        pattern: r"httpOnly\s*:\s*false|secure\s*:\s*false",
        unless_contains: &[],
        cwe: &["CWE-1004", "CWE-614"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/1004.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-026",
        title: "Небезопасная десериализация через node-serialize",
        description: "unserialize() в node-serialize исполняет функции, закодированные в данных. Это известный вектор RCE.",
        recommendation: "Используйте JSON.parse(). Библиотеку node-serialize применять для недоверенных данных нельзя.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: JS_FAMILY,
        pattern: r"(?:node-serialize|serialize)\.unserialize\s*\(",
        unless_contains: &[],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-027",
        title: "Модуль vm не является песочницей",
        description: "vm.runInNewContext() не изолирует код: через конструкторы и прототипы из него можно выбраться в основной контекст процесса.",
        recommendation: "Для недоверенного кода используйте отдельный процесс с ограничениями или изолированную среду (isolated-vm, WebAssembly).",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: JS_FAMILY,
        pattern: r"vm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(",
        unless_contains: &[],
        cwe: &["CWE-94", "CWE-265"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://nodejs.org/api/vm.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-028",
        title: "Регулярное выражение с риском катастрофического бэктрекинга (ReDoS)",
        description: "Вложенные квантификаторы вида (a+)+ на специально подобранной строке приводят к экспоненциальному времени разбора и блокируют event loop.",
        recommendation: "Упростите выражение, уберите вложенные квантификаторы. Ограничьте длину входа или используйте RE2-совместимый движок.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "Отказ в обслуживании",
        languages: JS_FAMILY,
        pattern: r"\([^)]*[+*]\)[+*]",
        unless_contains: &[],
        cwe: &["CWE-1333", "CWE-400"],
        owasp: Some(OWASP_DESIGN),
        references: &["https://cwe.mitre.org/data/definitions/1333.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-JS-029",
        title: "NoSQL-инъекция через $where",
        description: "Оператор $where в MongoDB выполняет JavaScript на сервере БД. Данные пользователя в его значении дают инъекцию кода и обход фильтров запроса.",
        recommendation: "Не используйте $where. Стройте условия обычными операторами ($eq, $in) и приводите типы параметров запроса.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "SQL-инъекция",
        languages: JS_FAMILY,
        pattern: r#"["']?\$where["']?\s*:"#,
        unless_contains: &[],
        cwe: &["CWE-943"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/943.html"],
        skip_in_tests: false,
    },

    // ------------------------------------------------------------------ Rust
    Rule {
        id: "VS-RS-001",
        title: "Блок unsafe",
        description: "В unsafe компилятор не проверяет корректность работы с памятью. Ошибка здесь — это UB: порча памяти, эксплуатируемые падения.",
        recommendation: "Проверьте, что инварианты действительно соблюдены, и опишите их в комментарии // SAFETY:. По возможности замените безопасным аналогом.",
        severity: Severity::Info,
        confidence: Confidence::High,
        category: "Безопасность памяти",
        languages: RS,
        pattern: r"\bunsafe\s*\{",
        unless_contains: &[],
        cwe: &["CWE-119"],
        owasp: None,
        references: &["https://doc.rust-lang.org/nomicon/"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-RS-002",
        title: "std::mem::transmute",
        description: "transmute переинтерпретирует байты одного типа как другой без каких-либо проверок. Несовпадение размера или инвариантов типа — мгновенное UB.",
        recommendation: "Используйте безопасные преобразования: as для чисел, from_le_bytes для байтов, крейты bytemuck/zerocopy для POD-типов.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Безопасность памяти",
        languages: RS,
        pattern: r"(?:std::)?mem::transmute\s*(?:::<[^>]*>)?\s*\(",
        unless_contains: &[],
        cwe: &["CWE-704"],
        owasp: None,
        references: &["https://doc.rust-lang.org/std/mem/fn.transmute.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-RS-003",
        title: "from_utf8_unchecked без проверки",
        description: "Функция создаёт &str из байтов, не проверяя UTF-8. Невалидные байты ломают инвариант str и приводят к UB при дальнейшей работе со строкой.",
        recommendation: "Используйте std::str::from_utf8(bytes)? и обработайте ошибку, либо String::from_utf8_lossy() для «best effort».",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Безопасность памяти",
        languages: RS,
        pattern: r"from_utf8_unchecked\s*\(",
        unless_contains: &[],
        cwe: &["CWE-20"],
        owasp: None,
        references: &["https://doc.rust-lang.org/std/str/fn.from_utf8_unchecked.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RS-004",
        title: "get_unchecked — доступ без проверки границ",
        description: "Метод читает элемент без проверки индекса. Выход за границы даёт чтение чужой памяти или падение — это UB, а не паника.",
        recommendation: "Используйте обычную индексацию или .get(i), который вернёт Option. Оптимизация оправдана только на измеренном горячем пути.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Безопасность памяти",
        languages: RS,
        pattern: r"get_unchecked(?:_mut)?\s*\(",
        unless_contains: &[],
        cwe: &["CWE-125", "CWE-787"],
        owasp: None,
        references: &["https://cwe.mitre.org/data/definitions/125.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RS-005",
        title: "Команда запускается через шелл (sh -c / cmd /C)",
        description: "Передача строки в sh -c возвращает разбор метасимволов шеллу. Пользовательские данные в такой строке дают инъекцию команд.",
        recommendation: "Вызывайте программу напрямую: Command::new(\"git\").arg(\"log\").arg(&branch) — аргументы передаются как есть, без шелла.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: RS,
        pattern: r#"Command::new\s*\(\s*["'](?:sh|bash|zsh|cmd|powershell|/bin/sh|/bin/bash)["']"#,
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RS-006",
        title: "reqwest принимает недействительные сертификаты",
        description: "danger_accept_invalid_certs(true) отключает проверку сертификата. Соединение больше не защищено от man-in-the-middle.",
        recommendation: "Уберите опцию. Для внутреннего CA добавьте корневой сертификат: .add_root_certificate(Certificate::from_pem(&pem)?).",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: RS,
        pattern: r"danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RS-007",
        title: "SQL-запрос собирается format!",
        description: "format! не экранирует кавычки, поэтому подстановка пользовательских данных в текст SQL приводит к инъекции.",
        recommendation: "Используйте параметры драйвера: sqlx::query(\"SELECT * FROM t WHERE id = $1\").bind(id) или query! с проверкой на этапе компиляции.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "SQL-инъекция",
        languages: RS,
        pattern: r#"(?i)format!\s*\(\s*["'][^"']*(?:select |insert |update |delete |drop )"#,
        unless_contains: &[],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RS-008",
        title: "Слабый хеш (MD5/SHA-1)",
        description: "MD5 и SHA-1 уязвимы к коллизиям и не годятся для подписей и проверки целостности.",
        recommendation: "Используйте sha2::Sha256 или blake3. Для паролей — argon2 или bcrypt.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Криптография",
        languages: RS,
        pattern: r"\b(?:Md5|Sha1)::new\s*\(\s*\)|md5::compute\s*\(",
        unless_contains: &[],
        cwe: &["CWE-327", "CWE-328"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-RS-009",
        title: "unwrap() на результате разбора внешних данных",
        description: "unwrap() на данных извне (переменные окружения, парсинг ввода, сеть) превращает некорректный вход в панику. Для сервиса это отказ в обслуживании.",
        recommendation: "Обработайте ошибку: ? с anyhow/thiserror, либо .unwrap_or_default() / .context(\"...\") с понятным сообщением.",
        severity: Severity::Low,
        confidence: Confidence::Low,
        category: "Обработка ошибок",
        languages: RS,
        pattern: r"(?:env::var|from_str|parse|from_utf8|read_to_string|recv|accept)\s*(?:::<[^>]*>)?\s*\([^)]*\)\s*\.\s*unwrap\s*\(\s*\)",
        unless_contains: &[],
        cwe: &["CWE-248"],
        owasp: Some(OWASP_DESIGN),
        references: &["https://cwe.mitre.org/data/definitions/248.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-RS-010",
        title: "Арифметика без контроля переполнения",
        description: "В release-сборке переполнение целого молча заворачивается по модулю. В расчётах размеров, индексов и балансов это приводит к логическим ошибкам и порче памяти.",
        recommendation: "Используйте checked_add/checked_mul и обрабатывайте None, либо saturating_/wrapping_ варианты, если поведение задумано.",
        severity: Severity::Low,
        confidence: Confidence::Low,
        category: "Целочисленное переполнение",
        languages: RS,
        pattern: r"\bas\s+(?:u8|u16|u32|usize|i8|i16|i32)\b",
        unless_contains: &[],
        cwe: &["CWE-190"],
        owasp: None,
        references: &["https://cwe.mitre.org/data/definitions/190.html"],
        skip_in_tests: true,
    },

    // ------------------------------------------------------------ Dockerfile
    Rule {
        id: "VS-DK-001",
        title: "Контейнер работает от root",
        description: "Без директивы USER процесс в контейнере идёт от root. При побеге из контейнера или монтировании томов это заметно повышает ущерб.",
        recommendation: "Добавьте непривилегированного пользователя: RUN adduser -D app && USER app.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Dockerfile],
        pattern: r"(?mi)^\s*USER\s+root",
        unless_contains: &[],
        cwe: &["CWE-250"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/250.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-DK-002",
        title: "Скачивание скрипта и запуск через пайп",
        description: "curl | sh выполняет всё, что вернёт сервер, без проверки. Компрометация источника или MITM означают выполнение произвольного кода при сборке.",
        recommendation: "Скачайте файл, проверьте контрольную сумму или подпись, и только потом запускайте.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Цепочка поставок",
        languages: &[Language::Dockerfile, Language::Shell],
        pattern: r"(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh",
        unless_contains: &[],
        cwe: &["CWE-494"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/494.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-DK-003",
        title: "Загрузка с отключённой проверкой сертификата",
        description: "Флаги --no-check-certificate и --insecure отключают проверку TLS при скачивании — содержимое можно подменить по пути.",
        recommendation: "Уберите флаг. Если мешает корпоративный CA, установите его сертификат в образ.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Цепочка поставок",
        languages: &[Language::Dockerfile, Language::Shell],
        pattern: r"--no-check-certificate|curl[^\n]*\s-[a-zA-Z]*k\b|--insecure",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-DK-004",
        title: "Базовый образ с тегом latest",
        description: "latest не фиксирует версию: сборка невоспроизводима, а обновление базового образа может незаметно втянуть уязвимость.",
        recommendation: "Фиксируйте версию, а лучше digest: FROM node:22.13-alpine@sha256:...",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Цепочка поставок",
        languages: &[Language::Dockerfile],
        pattern: r"(?mi)^\s*FROM\s+\S+:latest",
        unless_contains: &[],
        cwe: &["CWE-1104"],
        owasp: Some(OWASP_VULN_COMP),
        references: &["https://cwe.mitre.org/data/definitions/1104.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-DK-005",
        title: "ADD с удалённым URL",
        description: "ADD с http(s)-адресом скачивает файл при сборке без проверки контрольной суммы. Подмена источника или MITM втягивают чужое содержимое в образ.",
        recommendation: "Скачивайте через RUN curl с проверкой суммы, а для локальных файлов используйте COPY — ADD с URL непрозрачен.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Цепочка поставок",
        languages: &[Language::Dockerfile],
        pattern: r"(?mi)^\s*ADD\s+https?://",
        unless_contains: &[],
        cwe: &["CWE-494"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://docs.docker.com/reference/dockerfile/#add"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-DK-006",
        title: "Секрет задан в ENV/ARG",
        description: "Значение ENV или ARG остаётся в слоях образа и в истории сборки. Пароль или токен, заданный так, достанет любой, у кого есть образ.",
        recommendation: "Пробрасывайте секреты через RUN --mount=type=secret или переменные окружения при запуске, а не в Dockerfile.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Хранение секретов",
        languages: &[Language::Dockerfile],
        pattern: r"(?mi)^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)\w*(?:\s*=\s*|\s+)\S",
        unless_contains: &[],
        cwe: &["CWE-798"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/798.html"],
        skip_in_tests: false,
    },

    // ----------------------------------------------------------- Shell / CI
    Rule {
        id: "VS-SH-001",
        title: "eval в shell-скрипте",
        description: "eval исполняет собранную строку как команду. Любая переменная внутри неё, пришедшая извне, даёт инъекцию.",
        recommendation: "Избегайте eval. Используйте массивы аргументов и \"${var}\" в кавычках.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Shell],
        pattern: r"(?m)^\s*eval\s+",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SH-002",
        title: "Права 0777 через chmod",
        description: "chmod 777 даёт чтение, запись и исполнение любому пользователю. Локальный злоумышленник сможет подменить содержимое файла или скрипта.",
        recommendation: "Задавайте минимально необходимые права: 0644 для файлов, 0755 для исполняемых, 0600 для секретов.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Shell, Language::Dockerfile],
        pattern: r"(?i)chmod\s+(?:-R\s+)?0?777\b",
        unless_contains: &[],
        cwe: &["CWE-276"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/276.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CI-001",
        title: "GitHub Actions: pull_request_target",
        description: "Этот триггер даёт workflow доступ к секретам репозитория и выполняется в контексте базовой ветки. В связке с checkout кода из PR любой внешний контрибьютор может украсть секреты.",
        recommendation: "Используйте обычный pull_request. Если нужен именно pull_request_target — не делайте checkout кода из PR и не запускайте его сборку.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Цепочка поставок",
        languages: &[Language::Yaml],
        pattern: r"(?m)^\s*pull_request_target\s*:",
        unless_contains: &[],
        cwe: &["CWE-269"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CI-002",
        title: "GitHub Actions: сторонний action не зафиксирован по SHA",
        description: "Ссылка на тег или ветку означает, что владелец action может в любой момент подменить код, который выполняется с вашими секретами.",
        recommendation: "Фиксируйте action по полному SHA коммита: uses: actions/checkout@8f4b7f8... — тег можно оставить комментарием.",
        severity: Severity::Low,
        confidence: Confidence::Low,
        category: "Цепочка поставок",
        languages: &[Language::Yaml],
        pattern: r"(?m)uses\s*:\s*[\w.-]+/[\w.-]+@v?[\d.]+\s*$",
        unless_contains: &[],
        cwe: &["CWE-1357"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CI-003",
        title: "GitHub Actions: инъекция в run через выражение",
        description: "Подстановка ${{ github.event.*.title/body }} или github.head_ref прямо в run вставляет подконтрольный атакующему текст в шелл-скрипт шага — это инъекция команд в раннер.",
        recommendation: "Передавайте значение через env: и обращайтесь к нему как \"$VAR\" в кавычках — тогда подстановка не парсится шеллом.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Yaml],
        pattern: r"\$\{\{\s*github\.(?:event\.[\w.]*(?:title|body|message|email)|head_ref)\b",
        unless_contains: &[],
        cwe: &["CWE-94"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://securitylab.github.com/resources/github-actions-untrusted-input/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CI-004",
        title: "GitHub Actions: permissions write-all",
        description: "write-all выдаёт токену workflow права на запись во все области, включая содержимое репозитория. Скомпрометированный шаг сможет пушить код и менять релизы.",
        recommendation: "Задайте минимальные права явно: permissions: { contents: read } на уровне workflow, расширяя точечно там, где нужно.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Yaml],
        pattern: r"(?mi)^\s*permissions:\s*write-all\b",
        unless_contains: &[],
        cwe: &["CWE-269"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.github.com/en/actions/security-guides/automatic-token-authentication"],
        skip_in_tests: false,
    },

    // -------------------------------------------------------------------- Go
    Rule {
        id: "VS-GO-001",
        title: "Команда запускается через шелл",
        description: "exec.Command(\"sh\", \"-c\", ...) отдаёт разбор строки шеллу, поэтому метасимволы в аргументах интерпретируются. Пользовательский ввод даёт инъекцию команд.",
        recommendation: "Вызывайте программу напрямую: exec.Command(\"git\", \"log\", branch) — аргументы передаются как есть, без шелла.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Go],
        pattern: r#"exec\.Command\s*\(\s*["'](?:sh|bash|zsh|cmd|powershell|/bin/sh|/bin/bash)["']"#,
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-GO-002",
        title: "SQL-запрос собирается конкатенацией или Sprintf",
        description: "Склейка значений с текстом SQL не экранирует кавычки, поэтому пользовательский ввод может изменить структуру запроса.",
        recommendation: "Используйте плейсхолдеры драйвера: db.Query(\"SELECT * FROM t WHERE id = $1\", id).",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "SQL-инъекция",
        languages: &[Language::Go],
        pattern: r#"(?i)(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf\s*\(\s*)?["`][^"`]*(?:select |insert |update |delete |drop )"#,
        unless_contains: &["$1", "?", "$2"],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-GO-003",
        title: "Отключена проверка TLS-сертификата",
        description: "InsecureSkipVerify: true заставляет клиент принимать любой сертификат. Соединение перестаёт защищать от man-in-the-middle.",
        recommendation: "Уберите опцию. Для внутреннего CA добавьте его в RootCAs пула сертификатов.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Go],
        pattern: r"InsecureSkipVerify\s*:\s*true",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-GO-004",
        title: "Слабый хеш (MD5/SHA-1)",
        description: "MD5 и SHA-1 уязвимы к коллизиям и не годятся для подписей и проверки целостности.",
        recommendation: "Используйте sha256.New(). Для паролей — golang.org/x/crypto/bcrypt или argon2.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Криптография",
        languages: &[Language::Go],
        pattern: r"(?:md5|sha1)\.(?:New|Sum)\s*\(",
        unless_contains: &[],
        cwe: &["CWE-327", "CWE-328"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-GO-005",
        title: "Ошибка игнорируется присваиванием в _",
        description: "Go возвращает ошибки значением. Присваивание в _ отбрасывает её молча, и код продолжает работать с неинициализированными данными.",
        recommendation: "Обработайте ошибку: if err != nil { return fmt.Errorf(\"...: %w\", err) }.",
        severity: Severity::Low,
        confidence: Confidence::Low,
        category: "Обработка ошибок",
        languages: &[Language::Go],
        pattern: r"(?m)^\s*_,\s*_\s*(?::)?=\s*\w+",
        unless_contains: &[],
        cwe: &["CWE-390"],
        owasp: Some(OWASP_DESIGN),
        references: &["https://cwe.mitre.org/data/definitions/390.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-GO-006",
        title: "Слабый генератор случайных чисел",
        description: "math/rand — предсказуемый PRNG. Токены и ключи, полученные из него, восстанавливаются по нескольким значениям.",
        recommendation: "Для всего, что связано с безопасностью, используйте crypto/rand.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Криптография",
        languages: &[Language::Go],
        pattern: r#"math/rand"|rand\.(?:Intn|Int31|Int63|Float64)\s*\("#,
        unless_contains: &["crypto/rand"],
        cwe: &["CWE-338"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/338.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-GO-007",
        title: "Слабый шифр (DES/RC4)",
        description: "DES с 56-битным ключом перебирается, а поток RC4 имеет статистические смещения. Оба алгоритма считаются сломанными.",
        recommendation: "Используйте AES-GCM через crypto/aes и crypto/cipher со случайным nonce на каждое сообщение.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Go],
        pattern: r"(?:des|rc4)\.NewCipher\s*\(",
        unless_contains: &[],
        cwe: &["CWE-327"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-GO-008",
        title: "Приведение к template.HTML отключает экранирование",
        description: "Значения типов template.HTML/JS/URL вставляются в шаблон без автоэкранирования. Если в них попадает пользовательский ввод, это XSS.",
        recommendation: "Не приводите пользовательские данные к template.HTML. Пусть html/template экранирует их сам, передавая как обычную строку.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "XSS",
        languages: &[Language::Go],
        pattern: r"\btemplate\.(?:HTML|JS|URL|CSS)\s*\(",
        unless_contains: &[],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-GO-009",
        title: "Файл создаётся с правами 0777",
        description: "Права 0777 дают чтение, запись и исполнение любому пользователю системы. Локальный злоумышленник сможет подменить содержимое файла.",
        recommendation: "Задавайте минимально необходимые права: 0600 для приватных файлов, 0644 для читаемых, 0700 для каталогов.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Go],
        pattern: r"(?:Chmod|MkdirAll|WriteFile|OpenFile|Mkdir)\s*\([^)]*0o?777",
        unless_contains: &[],
        cwe: &["CWE-276"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/276.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-GO-010",
        title: "SSH: проверка ключа хоста отключена",
        description: "ssh.InsecureIgnoreHostKey принимает любой ключ сервера. Соединение перестаёт защищать от man-in-the-middle.",
        recommendation: "Используйте ssh.FixedHostKey или knownhosts.New с заранее известными ключами хостов.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Go],
        pattern: r"ssh\.InsecureIgnoreHostKey\b",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },

    // ------------------------------------------------------------------ Java
    Rule {
        id: "VS-JV-001",
        title: "Runtime.exec() — выполнение внешней команды",
        description: "Передача собранной строки в Runtime.exec() позволяет подставить в неё пользовательские данные, что даёт инъекцию команд.",
        recommendation: "Используйте ProcessBuilder со списком аргументов и никогда не склеивайте команду из строк.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-002",
        title: "SQL-запрос собирается конкатенацией",
        description: "Склейка значений с текстом SQL через + позволяет атакующему дописать свои конструкции в запрос.",
        recommendation: "Используйте PreparedStatement с параметрами: ps.setString(1, name).",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "SQL-инъекция",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"(?i)(?:executeQuery|executeUpdate|execute)\s*\(\s*["'][^"']*(?:select |insert |update |delete )[^"']*["']\s*\+"#,
        unless_contains: &[],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-003",
        title: "Десериализация через ObjectInputStream",
        description: "readObject() восстанавливает произвольные классы и вызывает их методы. На недоверенных данных это классический вектор RCE в Java.",
        recommendation: "Не десериализуйте недоверенные данные. Используйте JSON с явной схемой или ObjectInputFilter с белым списком классов.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)",
        unless_contains: &["ObjectInputFilter", "setObjectInputFilter"],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-004",
        title: "Разбор XML уязвим к XXE",
        description: "Парсеры XML в Java по умолчанию раскрывают внешние сущности, что даёт чтение локальных файлов и SSRF.",
        recommendation: "Отключите внешние сущности: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true).",
        severity: Severity::High,
        confidence: Confidence::Low,
        category: "XXE",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(",
        unless_contains: &["disallow-doctype-decl", "setFeature", "IS_SUPPORTING_EXTERNAL_ENTITIES"],
        cwe: &["CWE-611"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/611.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-005",
        title: "Слабый хеш (MD5/SHA-1)",
        description: "MD5 и SHA-1 подвержены коллизиям, их нельзя применять для подписей и проверки целостности.",
        recommendation: "Берите MessageDigest.getInstance(\"SHA-256\"). Для паролей — BCrypt или Argon2.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']"#,
        unless_contains: &[],
        cwe: &["CWE-327", "CWE-328"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-JV-006",
        title: "Шифрование в режиме ECB",
        description: "ECB шифрует одинаковые блоки одинаково, поэтому структура открытого текста видна в шифротексте.",
        recommendation: "Используйте AES/GCM/NoPadding со случайным IV на каждое сообщение.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"Cipher\.getInstance\s*\(\s*["'][^"']*ECB"#,
        unless_contains: &[],
        cwe: &["CWE-327"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-007",
        title: "Слабый шифр (DES/RC4)",
        description: "DES, RC4 и RC2 давно взломаны: короткий ключ или предсказуемый поток позволяют восстановить открытый текст.",
        recommendation: "Используйте Cipher.getInstance(\"AES/GCM/NoPadding\") со случайным IV на каждое сообщение.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"Cipher\.getInstance\s*\(\s*["'](?:DES|RC4|RC2|ARCFOUR|Blowfish)\b"#,
        unless_contains: &[],
        cwe: &["CWE-327"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-008",
        title: "Проверка имени хоста TLS отключена",
        description: "ALLOW_ALL_HOSTNAME_VERIFIER и NoopHostnameVerifier принимают сертификат для любого домена. Это открывает соединение для man-in-the-middle.",
        recommendation: "Уберите кастомный verifier и используйте проверку по умолчанию. Сертификат должен соответствовать хосту.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-009",
        title: "CORS разрешён для любого источника",
        description: "Разрешённый источник \"*\" позволяет любому сайту слать запросы с полномочиями пользователя. В связке с cookie это ведёт к краже данных.",
        recommendation: "Перечислите доверенные источники явным списком вместо \"*\". Не используйте wildcard с credentials.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"(?i)(?:setAllowedOrigins|allowedOrigins|allowedOriginPatterns)\s*\([^)]*["']\*["']"#,
        unless_contains: &[],
        cwe: &["CWE-942"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/942.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-010",
        title: "SnakeYAML: небезопасная загрузка",
        description: "new Yaml().load() с конструктором по умолчанию создаёт произвольные Java-объекты по тегам в YAML. На недоверенных данных это ведёт к выполнению кода.",
        recommendation: "Создавайте Yaml с SafeConstructor: new Yaml(new SafeConstructor(new LoaderOptions())).",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Небезопасная десериализация",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"new\s+Yaml\s*\([^)]*\)\s*\.\s*load",
        unless_contains: &["SafeConstructor"],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },

    // ------------------------------------------------------------------- PHP
    Rule {
        id: "VS-PH-001",
        title: "eval() — выполнение произвольного кода",
        description: "eval() исполняет строку как PHP. Любое влияние пользователя на аргумент означает полную компрометацию.",
        recommendation: "Уберите eval(). Для данных используйте json_decode(), для выбора поведения — массив-диспетчер.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Php],
        pattern: r"\beval\s*\(",
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PH-002",
        title: "Выполнение системной команды",
        description: "system(), exec(), shell_exec() и passthru() запускают команду через шелл. Пользовательский ввод в аргументе даёт инъекцию.",
        recommendation: "Экранируйте аргументы через escapeshellarg(), а лучше избегайте вызова внешних команд.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Php],
        pattern: r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
        unless_contains: &["escapeshellarg", "escapeshellcmd"],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-003",
        title: "SQL-запрос собирается интерполяцией",
        description: "Подстановка переменных в текст SQL не экранирует кавычки — это SQL-инъекция.",
        recommendation: "Используйте подготовленные запросы PDO: $stmt = $pdo->prepare(\"SELECT * FROM t WHERE id = ?\"); $stmt->execute([$id]).",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "SQL-инъекция",
        languages: &[Language::Php],
        pattern: r#"(?i)(?:mysqli_query|->query|->exec)\s*\(\s*["'][^"']*(?:select |insert |update |delete )[^"']*\$"#,
        unless_contains: &[],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-004",
        title: "Небезопасная десериализация",
        description: "unserialize() на недоверенных данных вызывает магические методы объектов и приводит к выполнению кода (POP-цепочки).",
        recommendation: "Используйте json_decode(). Если unserialize() необходим — ограничьте классы: unserialize($data, ['allowed_classes' => false]).",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: &[Language::Php],
        pattern: r"\bunserialize\s*\(",
        unless_contains: &["allowed_classes"],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://www.php.net/manual/en/function.unserialize.php"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-005",
        title: "Подключение файла по переменной (LFI/RFI)",
        description: "include/require с переменной в пути позволяет подключить произвольный файл, а при allow_url_include — и удалённый.",
        recommendation: "Подключайте только пути из белого списка. Никогда не передавайте пользовательский ввод в include.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Path traversal",
        languages: &[Language::Php],
        pattern: r"(?:include|require)(?:_once)?\s*(?:\(\s*)?\$",
        unless_contains: &[],
        cwe: &["CWE-98", "CWE-22"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/98.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-006",
        title: "Вывод суперглобала без экранирования (XSS)",
        description: "echo/print значения из $_GET, $_POST или $_REQUEST напрямую вставляет пользовательский ввод в HTML — это отражённый XSS.",
        recommendation: "Экранируйте вывод через htmlspecialchars($value, ENT_QUOTES) перед вставкой в страницу.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "XSS",
        languages: &[Language::Php],
        pattern: r"(?i)\b(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)\b",
        unless_contains: &["htmlspecialchars", "htmlentities"],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-007",
        title: "extract() на пользовательских данных",
        description: "extract($_GET/$_POST) создаёт переменные по ключам из запроса и может перезаписать уже существующие, подменяя логику и обходя проверки.",
        recommendation: "Не применяйте extract() к суперглобалам. Читайте нужные поля явно: $id = $_GET['id'].",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Контроль доступа",
        languages: &[Language::Php],
        pattern: r"extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)",
        unless_contains: &[],
        cwe: &["CWE-915"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/915.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-008",
        title: "preg_replace с модификатором /e",
        description: "Модификатор /e заставляет preg_replace выполнять замену как код PHP. На данных из запроса это выполнение произвольного кода.",
        recommendation: "Замените на preg_replace_callback() и формируйте результат в функции обратного вызова без eval.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Php],
        pattern: r#"preg_replace\s*\(\s*["'][^"']*/[a-zA-Z]*e[a-zA-Z]*["']"#,
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-009",
        title: "Открытый редирект / инъекция заголовка",
        description: "header(\"Location: ...\") с пользовательским вводом даёт открытый редирект, а перевод строки в значении — расщепление HTTP-ответа (HTTP response splitting).",
        recommendation: "Редиректьте только на пути из белого списка и вырезайте переводы строк из значения заголовка.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Открытый редирект",
        languages: &[Language::Php],
        pattern: r#"(?i)header\s*\(\s*["']location:[^)]*\$_(?:GET|POST|REQUEST|COOKIE)"#,
        unless_contains: &[],
        cwe: &["CWE-601", "CWE-113"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/601.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-010",
        title: "assert() со строковым аргументом",
        description: "assert() со строкой исполняет её как PHP-код. Пользовательский ввод в этой строке приводит к выполнению произвольного кода.",
        recommendation: "Не передавайте строки в assert(). Проверяйте условия обычными выражениями и бросайте исключения.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Php],
        pattern: r#"\bassert\s*\(\s*["']"#,
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: true,
    },

    // ------------------------------------------------------------------ Ruby
    Rule {
        id: "VS-RB-001",
        title: "Выполнение команды через шелл",
        description: "Обратные кавычки, system() и %x запускают команду через шелл. Интерполяция пользовательских данных даёт инъекцию.",
        recommendation: "Передавайте аргументы массивом: system(\"git\", \"log\", branch) — так шелл не участвует.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Ruby],
        pattern: r"(?:`[^`]*#\{|%x\[|%x\(|\bsystem\s*\(\s*[\x22'][^\x22']*#\{)",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-002",
        title: "SQL-запрос собирается интерполяцией",
        description: "Интерполяция #{} в where/find_by_sql не экранирует значения — это SQL-инъекция в Rails.",
        recommendation: "Передавайте параметры отдельно: where(\"id = ?\", id) или where(id: id).",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "SQL-инъекция",
        languages: &[Language::Ruby],
        pattern: r#"(?:where|find_by_sql|execute)\s*\(?\s*["'][^"']*#\{"#,
        unless_contains: &[],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://rails-sqli.org/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-003",
        title: "Небезопасная десериализация YAML/Marshal",
        description: "YAML.load и Marshal.load восстанавливают произвольные объекты Ruby и приводят к выполнению кода.",
        recommendation: "Используйте YAML.safe_load(data). Marshal на недоверенных данных применять нельзя.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: &[Language::Ruby],
        pattern: r"(?:YAML|Marshal)\.load\s*\(",
        unless_contains: &["safe_load"],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-004",
        title: "eval() — выполнение произвольного кода",
        description: "eval() исполняет строку как код Ruby. Если в неё попадают данные извне, это полная компрометация процесса.",
        recommendation: "Уберите eval(). Для выбора поведения используйте хэш-диспетчер или case, для данных — JSON.parse.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Ruby],
        pattern: r"\beval\s*\(",
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-RB-005",
        title: "html_safe / raw отключает экранирование во вью",
        description: "html_safe и raw помечают строку как безопасный HTML, и Rails вставляет её без экранирования. Пользовательский ввод в ней даёт XSS.",
        recommendation: "Не вызывайте html_safe на пользовательских данных. Для нужной разметки используйте sanitize с белым списком тегов.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "XSS",
        languages: &[Language::Ruby],
        pattern: r"\.html_safe\b|\braw\s*\(",
        unless_contains: &["sanitize"],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-RB-006",
        title: "Вызов метода по имени из запроса (send)",
        description: "send/public_send с именем метода из params позволяет вызвать любой метод объекта, включая приватные, — это обход логики и контроля доступа.",
        recommendation: "Сверяйте имя метода с белым списком перед вызовом или используйте явный case по допустимым действиям.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Контроль доступа",
        languages: &[Language::Ruby],
        pattern: r"\.(?:send|public_send|__send__)\s*\(\s*params\b",
        unless_contains: &[],
        cwe: &["CWE-749"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/749.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-007",
        title: "Открытый редирект через redirect_to",
        description: "redirect_to с адресом из params уводит пользователя на произвольный внешний сайт — основа фишинга и обхода доверенных доменов.",
        recommendation: "Разрешайте только относительные пути или проверяйте хост по белому списку; в Rails оставляйте allow_other_host по умолчанию выключенным.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Открытый редирект",
        languages: &[Language::Ruby],
        pattern: r"redirect_to\s+params\b",
        unless_contains: &[],
        cwe: &["CWE-601"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/601.html"],
        skip_in_tests: false,
    },

    // -------------------------------------------------------------------- C#
    Rule {
        id: "VS-CS-001",
        title: "SQL-запрос собирается конкатенацией или интерполяцией",
        description: "Склейка значений с текстом SQL не экранирует кавычки — пользовательский ввод меняет структуру запроса.",
        recommendation: "Используйте параметры: cmd.Parameters.AddWithValue(\"@id\", id).",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "SQL-инъекция",
        languages: &[Language::CSharp],
        pattern: r#"(?i)new\s+Sql(?:Command|DataAdapter)\s*\(\s*(?:\$)?["'][^"']*(?:select |insert |update |delete )"#,
        unless_contains: &["@"],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-002",
        title: "Небезопасная десериализация BinaryFormatter",
        description: "BinaryFormatter восстанавливает произвольные типы и признан небезопасным самим Microsoft — он удалён в .NET 9.",
        recommendation: "Перейдите на System.Text.Json или protobuf. BinaryFormatter применять нельзя.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: &[Language::CSharp],
        pattern: r"BinaryFormatter|LosFormatter|NetDataContractSerializer|SoapFormatter",
        unless_contains: &[],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-003",
        title: "Отключена проверка TLS-сертификата",
        description: "Возврат true из ServerCertificateValidationCallback принимает любой сертификат — соединение уязвимо к MITM.",
        recommendation: "Уберите колбэк. Для внутреннего CA установите его сертификат в хранилище доверия.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::CSharp],
        pattern: r"ServerCertificateValidationCallback\s*(?:\+)?=\s*(?:delegate|\()",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-004",
        title: "Команда запускается через шелл",
        description: "Process.Start с cmd.exe, powershell или /bin/sh отдаёт разбор строки шеллу. Подстановка данных извне даёт инъекцию команд.",
        recommendation: "Запускайте программу напрямую через ProcessStartInfo с Arguments-списком и UseShellExecute = false.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::CSharp],
        pattern: r#"(?i)Process\.Start\s*\(\s*(?:new\s+ProcessStartInfo\s*\(\s*)?["'](?:cmd|cmd\.exe|powershell|powershell\.exe|/bin/sh|/bin/bash|bash)["']"#,
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-005",
        title: "Слабый хеш (MD5/SHA-1)",
        description: "MD5 и SHA-1 подвержены коллизиям и не годятся для подписей и проверки целостности.",
        recommendation: "Используйте SHA256.Create(). Для паролей — PBKDF2 (Rfc2898DeriveBytes), bcrypt или Argon2.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::CSharp],
        pattern: r"(?:MD5|SHA1)\.Create\s*\(|new\s+(?:MD5|SHA1)CryptoServiceProvider",
        unless_contains: &[],
        cwe: &["CWE-327", "CWE-328"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-CS-006",
        title: "Устаревшая версия TLS/SSL",
        description: "SSL 3.0 и TLS 1.0/1.1 содержат известные уязвимости (POODLE, BEAST) и выведены из эксплуатации.",
        recommendation: "Не задавайте SecurityProtocol вручную — пусть ОС выберет актуальную версию, либо укажите Tls12/Tls13.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::CSharp],
        pattern: r"SecurityProtocolType\.(?:Ssl3|Tls11|Tls)\b",
        unless_contains: &[],
        cwe: &["CWE-326"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/326.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-007",
        title: "Отключена проверка TLS-сертификата (HttpClient)",
        description: "ServerCertificateCustomValidationCallback, возвращающий true, или DangerousAcceptAnyServerCertificateValidator заставляют HttpClient принять любой сертификат — соединение уязвимо к MITM.",
        recommendation: "Уберите колбэк. Для внутреннего CA добавьте его сертификат в доверенное хранилище.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::CSharp],
        pattern: r"ServerCertificateCustomValidationCallback|DangerousAcceptAnyServerCertificateValidator",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-008",
        title: "Открытый редирект через Response.Redirect",
        description: "Response.Redirect с адресом из запроса уводит пользователя на произвольный сайт — вектор фишинга и обхода доверенных доменов.",
        recommendation: "Разрешайте только локальные адреса: проверяйте Url.IsLocalUrl(target) перед редиректом.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Открытый редирект",
        languages: &[Language::CSharp],
        pattern: r"(?i)Response\.Redirect\s*\(\s*(?:Request\.|[\w]*\.QueryString|[\w]*\.Query\b)",
        unless_contains: &[],
        cwe: &["CWE-601"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/601.html"],
        skip_in_tests: false,
    },

    // ----------------------------------------------------------------- C/C++
    Rule {
        id: "VS-C-001",
        title: "Небезопасная функция копирования строк",
        description: "strcpy, strcat, sprintf и gets не проверяют размер буфера. Это классическое переполнение буфера с перезаписью стека.",
        recommendation: "Используйте strncpy/strncat/snprintf с явным размером, а лучше std::string в C++. gets() удалён из стандарта C11.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Безопасность памяти",
        languages: &[Language::C, Language::Cpp],
        pattern: r"\b(?:strcpy|strcat|sprintf|gets|vsprintf)\s*\(",
        unless_contains: &[],
        cwe: &["CWE-120", "CWE-787"],
        owasp: None,
        references: &["https://cwe.mitre.org/data/definitions/120.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-C-002",
        title: "Форматная строка из переменной",
        description: "printf(var) вместо printf(\"%s\", var) позволяет через %n и %x читать и писать память — это атака на форматную строку.",
        recommendation: "Всегда указывайте формат явно: printf(\"%s\", user_input).",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Безопасность памяти",
        languages: &[Language::C, Language::Cpp],
        pattern: r"\b(?:printf|fprintf|syslog)\s*\(\s*[a-z_][a-z0-9_]*\s*\)",
        unless_contains: &[],
        cwe: &["CWE-134"],
        owasp: None,
        references: &["https://cwe.mitre.org/data/definitions/134.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-C-003",
        title: "Вызов system() с собранной строкой",
        description: "system() выполняет команду через шелл. Данные извне в этой строке дают инъекцию команд.",
        recommendation: "Используйте execve() с массивом аргументов вместо system().",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::C, Language::Cpp],
        pattern: r"\bsystem\s*\(",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-C-004",
        title: "scanf(\"%s\") без ограничения длины",
        description: "%s в scanf/sscanf без ширины поля читает ввод любой длины в буфер фиксированного размера — переполнение буфера.",
        recommendation: "Указывайте максимальную ширину: scanf(\"%63s\", buf) для буфера в 64 байта, либо используйте fgets.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Безопасность памяти",
        languages: &[Language::C, Language::Cpp],
        pattern: r#"\b(?:scanf|sscanf|fscanf)\s*\(\s*[^;]*%s"#,
        unless_contains: &[],
        cwe: &["CWE-120"],
        owasp: None,
        references: &["https://cwe.mitre.org/data/definitions/120.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-C-005",
        title: "Небезопасное создание временного файла",
        description: "tmpnam, tempnam и mktemp возвращают имя, но не создают файл атомарно. Между проверкой и открытием возможна подмена (race, символическая ссылка).",
        recommendation: "Используйте mkstemp(), который создаёт и открывает файл одним атомарным вызовом.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Работа с файлами",
        languages: &[Language::C, Language::Cpp],
        pattern: r"\b(?:tmpnam|tempnam|mktemp)\s*\(",
        unless_contains: &[],
        cwe: &["CWE-377"],
        owasp: None,
        references: &["https://cwe.mitre.org/data/definitions/377.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-C-006",
        title: "Слабый генератор случайных чисел",
        description: "rand()/random() — предсказуемые PRNG. Токены, ключи и соли, полученные из них, восстанавливаются по нескольким значениям.",
        recommendation: "Для безопасности используйте getrandom(2), /dev/urandom или arc4random.",
        severity: Severity::Low,
        confidence: Confidence::Low,
        category: "Криптография",
        languages: &[Language::C, Language::Cpp],
        pattern: r"\b(?:rand|random|srand)\s*\(",
        unless_contains: &["arc4random", "getrandom"],
        cwe: &["CWE-338"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/338.html"],
        skip_in_tests: true,
    },

    // ----------------------------------------------------------------- Swift
    Rule {
        id: "VS-SW-001",
        title: "Использование устаревшего UIWebView",
        description: "UIWebView снят с поддержки Apple и не получает исправлений безопасности. Он не изолирует контент от приложения и уязвим к инъекциям.",
        recommendation: "Перейдите на WKWebView: он выполняет контент в отдельном процессе и поддерживает современные политики безопасности.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Swift],
        pattern: r"\bUIWebView\b",
        unless_contains: &[],
        cwe: &["CWE-1104"],
        owasp: Some(OWASP_VULN_COMP),
        references: &["https://cwe.mitre.org/data/definitions/1104.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SW-002",
        title: "Инъекция JavaScript во webview",
        description: "stringByEvaluatingJavaScriptFromString и evaluateJavaScript с интерполяцией вставляют данные прямо в исполняемый JS. Пользовательский ввод здесь даёт инъекцию скрипта.",
        recommendation: "Не собирайте JS из строк. Передавайте данные через WKScriptMessageHandler или postMessage, экранируя значения.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "XSS",
        languages: &[Language::Swift],
        pattern: r#"stringByEvaluatingJavaScriptFromString|evaluateJavaScript\s*\(\s*"[^"]*\\\("#,
        unless_contains: &[],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SW-003",
        title: "Слабый хеш (MD5/SHA-1)",
        description: "MD5 и SHA-1 подвержены коллизиям и не годятся для подписей и проверки целостности.",
        recommendation: "Используйте SHA-256 (CryptoKit: SHA256). Для паролей — bcrypt или Argon2 через проверенную библиотеку.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Swift],
        pattern: r"\bCC_MD5\b|\bCC_SHA1\b|Insecure\.(?:MD5|SHA1)\b",
        unless_contains: &[],
        cwe: &["CWE-327", "CWE-328"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-SW-004",
        title: "Секрет в UserDefaults",
        description: "UserDefaults хранит данные в незашифрованном plist. Пароль, токен или ключ там доступен любому, кто получит устройство или бэкап.",
        recommendation: "Храните секреты в Keychain (kSecClassGenericPassword), а не в UserDefaults.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Хранение секретов",
        languages: &[Language::Swift],
        pattern: r#"(?i)UserDefaults[^\n]*\.set\s*\([^\n)]*forKey:\s*"[^"]*(?:password|token|secret|apikey|api_key|credential)"#,
        unless_contains: &[],
        cwe: &["CWE-312"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/312.html"],
        skip_in_tests: false,
    },

    // ----------------------------------------------------------------- Scala
    Rule {
        id: "VS-SC-001",
        title: "SQL-запрос собирается s-интерполяцией",
        description: "Интерполятор s\"...$x...\" просто вставляет значение в строку, не экранируя его. Переданный так в запрос пользовательский ввод меняет структуру SQL.",
        recommendation: "Используйте параметризованные запросы фреймворка: интерполятор sql\"...\" в Slick/Doobie/Anorm подставляет значения как параметры.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "SQL-инъекция",
        languages: &[Language::Scala],
        pattern: r#"(?i)s"[^"]*(?:select |insert |update |delete )[^"]*\$"#,
        unless_contains: &[],
        cwe: &["CWE-89"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/89.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SC-002",
        title: "Слабый хеш (MD5/SHA-1)",
        description: "MD5 и SHA-1 подвержены коллизиям, их нельзя применять для подписей и проверки целостности.",
        recommendation: "Берите MessageDigest.getInstance(\"SHA-256\"). Для паролей — BCrypt или Argon2.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Scala],
        pattern: r#"MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']"#,
        unless_contains: &[],
        cwe: &["CWE-327", "CWE-328"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-SC-003",
        title: "Десериализация через ObjectInputStream",
        description: "readObject() восстанавливает произвольные классы и вызывает их методы. На недоверенных данных это классический вектор RCE в Java.",
        recommendation: "Не десериализуйте недоверенные данные. Используйте JSON с явной схемой или ObjectInputFilter с белым списком классов.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: &[Language::Scala],
        pattern: r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)",
        unless_contains: &["ObjectInputFilter", "setObjectInputFilter"],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },

    // ------------------------------------------------------------------ Perl
    Rule {
        id: "VS-PL-001",
        title: "Команда с интерполяцией в шелл",
        description: "Обратные кавычки, system и qx выполняют строку через шелл. Интерполяция переменной в неё даёт инъекцию команд.",
        recommendation: "Вызывайте system списком аргументов: system(\"git\", \"log\", $branch) — тогда шелл не участвует.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Perl],
        pattern: r#"`[^`]*\$[\w{]|\b(?:system|exec)\s*\(?\s*["'][^"']*\$|\bqx[\(\{/\[]"#,
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PL-002",
        title: "Двухаргументный open с переменной",
        description: "open(FH, $path) в двухаргументной форме трактует спецсимволы в $path: ведущий или замыкающий | запускает команду, а > < меняют режим. Это инъекция команд и обход доступа.",
        recommendation: "Используйте трёхаргументный open с явным режимом: open(my $fh, \"<\", $path).",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Perl],
        pattern: r"\bopen\s*\(\s*\*?\w+\s*,\s*\$\w+\s*\)",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },

    // ------------------------------------------------------------------- Lua
    Rule {
        id: "VS-LU-001",
        title: "Команда через os.execute / io.popen",
        description: "os.execute и io.popen запускают строку через шелл. Склейка пользовательских данных в неё приводит к инъекции команд.",
        recommendation: "Избегайте os.execute с собранной строкой. Проверяйте ввод по белому списку и не передавайте его в шелл.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Lua],
        pattern: r"\bos\.execute\s*\(|\bio\.popen\s*\(",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-LU-002",
        title: "Динамический код через load / loadstring",
        description: "load и loadstring компилируют строку в функцию. Если в строку попадают внешние данные, это выполнение произвольного кода.",
        recommendation: "Не компилируйте код из данных. Для конфигурации используйте разбор JSON, для поведения — таблицу-диспетчер.",
        severity: Severity::High,
        confidence: Confidence::Low,
        category: "Выполнение кода",
        languages: &[Language::Lua],
        pattern: r"\bloadstring\s*\(|\bload\s*\(",
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: true,
    },

    // ---------------------------------------------------------------- Elixir
    Rule {
        id: "VS-EX-001",
        title: "Команда через шелл (:os.cmd / System.shell)",
        description: ":os.cmd и System.shell выполняют строку через системный шелл, интерпретируя метасимволы. Пользовательский ввод в ней даёт инъекцию команд.",
        recommendation: "Используйте System.cmd(\"git\", [\"log\", branch]) со списком аргументов — он не запускает шелл.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Elixir],
        pattern: r":os\.cmd\s*\(|System\.shell\s*\(",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-EX-002",
        title: "Выполнение кода через Code.eval_string",
        description: "Code.eval_string и Code.eval_quoted компилируют и исполняют переданный код. Внешние данные в аргументе означают выполнение произвольного кода.",
        recommendation: "Не выполняйте код из данных. Для динамического выбора используйте apply/3 по проверенному белому списку функций.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Elixir],
        pattern: r"Code\.eval_(?:string|quoted)\s*\(",
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-EX-003",
        title: "Небезопасная десериализация binary_to_term",
        description: ":erlang.binary_to_term без опции :safe воссоздаёт произвольные термы, включая функции и атомы, что ведёт к исчерпанию атомов и выполнению кода.",
        recommendation: "Передавайте опцию [:safe]: binary_to_term(data, [:safe]). Недоверенные данные так десериализовать нельзя вовсе.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Небезопасная десериализация",
        languages: &[Language::Elixir],
        pattern: r"binary_to_term\s*\(",
        unless_contains: &[":safe"],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },

    // ----------------------------------------------------------------- Nginx
    Rule {
        id: "VS-NG-001",
        title: "server_tokens включён",
        description: "server_tokens on раскрывает точную версию nginx в заголовках и на страницах ошибок, упрощая подбор известных эксплойтов под неё.",
        recommendation: "Задайте server_tokens off в блоке http.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Утечка данных",
        languages: &[Language::Nginx],
        pattern: r"(?mi)^\s*server_tokens\s+on\b",
        unless_contains: &[],
        cwe: &["CWE-200"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/200.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-NG-002",
        title: "Устаревшие протоколы TLS",
        description: "SSLv3 и TLS 1.0/1.1 содержат известные уязвимости (POODLE, BEAST) и выведены из эксплуатации.",
        recommendation: "Оставьте только современные версии: ssl_protocols TLSv1.2 TLSv1.3;",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Nginx],
        pattern: r"(?mi)^\s*ssl_protocols\s+[^;]*(?:SSLv2|SSLv3|TLSv1\.1|TLSv1[\s;])",
        unless_contains: &[],
        cwe: &["CWE-326"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/326.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-NG-003",
        title: "Слабые TLS-шифры",
        description: "Наборы с NULL, RC4, DES, MD5, EXPORT или aNULL не обеспечивают конфиденциальности и целостности соединения.",
        recommendation: "Ограничьте ssl_ciphers современными AEAD-наборами и включите ssl_prefer_server_ciphers on.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Криптография",
        languages: &[Language::Nginx],
        pattern: r"(?mi)^\s*ssl_ciphers\s+[^;]*(?:NULL|RC4|3?DES|MD5|EXPORT|aNULL|eNULL)",
        unless_contains: &[],
        cwe: &["CWE-327"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-NG-004",
        title: "Включён листинг каталога (autoindex)",
        description: "autoindex on отдаёт список файлов каталога без index-файла, раскрывая структуру и файлы, которые не предназначались для публикации.",
        recommendation: "Уберите autoindex on там, где листинг не нужен намеренно.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Nginx],
        pattern: r"(?mi)^\s*autoindex\s+on\b",
        unless_contains: &[],
        cwe: &["CWE-548"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/548.html"],
        skip_in_tests: false,
    },

    // ------------------------------------------------------------ Vue / Svelte
    Rule {
        id: "VS-VU-001",
        title: "Vue: v-html вставляет сырой HTML",
        description: "Директива v-html рендерит значение как HTML без экранирования. Пользовательские данные в ней приводят к XSS.",
        recommendation: "Выводите данные через {{ }} — Vue их экранирует. Для доверенной разметки очищайте её DOMPurify перед вставкой.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "XSS",
        languages: &[Language::Vue],
        pattern: r"\bv-html\b",
        unless_contains: &[],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-SV-001",
        title: "Svelte: {@html} вставляет сырой HTML",
        description: "Блок {@html expr} рендерит значение как HTML без экранирования. Пользовательские данные в нём приводят к XSS.",
        recommendation: "Выводите данные обычной интерполяцией {expr} — Svelte их экранирует. Для доверенной разметки очищайте её DOMPurify.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "XSS",
        languages: &[Language::Svelte],
        pattern: r"\{@html\b",
        unless_contains: &[],
        cwe: &["CWE-79"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/79.html"],
        skip_in_tests: true,
    },

    // ------------------------------------------------------------- Terraform
    Rule {
        id: "VS-TF-001",
        title: "Ресурс открыт всему интернету",
        description: "0.0.0.0/0 в правиле безопасности открывает порт для всего интернета. Для SSH, RDP или БД это прямой путь к перебору и эксплуатации.",
        recommendation: "Ограничьте cidr_blocks конкретными подсетями. Для админ-доступа используйте VPN или bastion.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r#"cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0/0["']"#,
        unless_contains: &[],
        cwe: &["CWE-284"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/284.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-002",
        title: "Публичный доступ к бакету",
        description: "acl = \"public-read\" делает содержимое бакета доступным любому. Это самая частая причина утечек данных в облаках.",
        recommendation: "Используйте private ACL и выдавайте доступ через presigned URL или CloudFront с OAI.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r#"acl\s*=\s*["']public-(?:read|read-write)["']"#,
        unless_contains: &[],
        cwe: &["CWE-284"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/284.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-003",
        title: "Шифрование отключено",
        description: "Явное отключение шифрования оставляет данные в хранилище в открытом виде.",
        recommendation: "Включите шифрование: encrypted = true, а для управляемых ключей укажите kms_key_id.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Terraform],
        pattern: r"(?:encrypted|encryption_enabled|storage_encrypted)\s*=\s*false",
        unless_contains: &[],
        cwe: &["CWE-311"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/311.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-004",
        title: "Секрет в открытом виде в конфигурации",
        description: "Пароли и ключи в .tf попадают в репозиторий и в state-файл. Terraform state хранит их без шифрования.",
        recommendation: "Используйте переменные с sensitive = true и подставляйте значения из Vault, AWS Secrets Manager или переменных окружения.",
        severity: Severity::High,
        confidence: Confidence::Low,
        category: "Секрет в коде",
        languages: &[Language::Terraform],
        pattern: r#"(?i)(?:password|secret_key|access_key|private_key)\s*=\s*["'][^"'$][^"']{7,}["']"#,
        unless_contains: &["var.", "data.", "local.", "random_"],
        cwe: &["CWE-798"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/798.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-005",
        title: "IAM-политика с действием \"*\"",
        description: "Action = \"*\" (часто вместе с Resource \"*\") даёт полный доступ ко всем операциям сервиса. Скомпрометированный принципал получает права администратора.",
        recommendation: "Перечислите только нужные действия и ограничьте Resource конкретными ARN — принцип наименьших привилегий.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Контроль доступа",
        languages: &[Language::Terraform],
        pattern: r#"(?i)(?:"Action"|actions)\s*[:=]\s*\[?\s*["']\*["']"#,
        unless_contains: &[],
        cwe: &["CWE-732"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/732.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-006",
        title: "База данных доступна из интернета",
        description: "publicly_accessible = true выдаёт инстансу БД публичный адрес. В связке с открытой security group это выставляет базу наружу.",
        recommendation: "Задайте publicly_accessible = false и держите БД в приватной подсети, доступной только из приложения.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"(?mi)publicly_accessible\s*=\s*true",
        unless_contains: &[],
        cwe: &["CWE-668"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/668.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-007",
        title: "Разрешён IMDSv1 (метаданные без токена)",
        description: "http_tokens = \"optional\" оставляет доступным IMDSv1. При SSRF на инстансе это позволяет украсть временные креды роли через сервис метаданных.",
        recommendation: "Требуйте IMDSv2: в metadata_options задайте http_tokens = \"required\".",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r#"(?mi)http_tokens\s*=\s*"optional""#,
        unless_contains: &[],
        cwe: &["CWE-16"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"],
        skip_in_tests: false,
    },

    // ------------------------------------------------------------ Kubernetes
    Rule {
        id: "VS-K8-001",
        title: "Контейнер запущен привилегированным",
        description: "privileged: true даёт контейнеру доступ ко всем устройствам хоста и снимает почти всю изоляцию. Побег из такого контейнера тривиален.",
        recommendation: "Уберите privileged. Если нужны отдельные возможности — выдайте их точечно через capabilities.add.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"privileged\s*:\s*true",
        unless_contains: &[],
        cwe: &["CWE-250"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-K8-002",
        title: "Разрешено повышение привилегий",
        description: "allowPrivilegeEscalation: true позволяет процессу получить больше прав, чем у родителя, через setuid-бинарники.",
        recommendation: "Задайте allowPrivilegeEscalation: false в securityContext.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"allowPrivilegeEscalation\s*:\s*true",
        unless_contains: &[],
        cwe: &["CWE-250"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-K8-003",
        title: "Монтирование хостовой файловой системы",
        description: "hostPath пробрасывает каталог узла в контейнер. Монтирование / или /var/run/docker.sock равносильно выдаче прав root на узле.",
        recommendation: "Используйте PersistentVolume или emptyDir. hostPath оправдан только для системных DaemonSet.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"hostPath\s*:",
        unless_contains: &[],
        cwe: &["CWE-668"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-K8-004",
        title: "Контейнер работает от root",
        description: "runAsUser: 0 запускает процесс от root внутри контейнера, что усиливает последствия любой уязвимости в нём.",
        recommendation: "Задайте runAsNonRoot: true и конкретный runAsUser.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false",
        unless_contains: &[],
        cwe: &["CWE-250"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        skip_in_tests: false,
    },

    // ------------------------------------------------------------ PowerShell
    Rule {
        id: "VS-PS-001",
        title: "Invoke-Expression с собранной строкой",
        description: "Invoke-Expression исполняет строку как код PowerShell — это прямой аналог eval.",
        recommendation: "Уберите Invoke-Expression. Вызывайте команды напрямую с параметрами через splatting.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::PowerShell],
        pattern: r"\b(?:Invoke-Expression|iex)\s+",
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PS-002",
        title: "Отключена проверка TLS-сертификата",
        description: "SkipCertificateCheck и подмена CertificatePolicy принимают любой сертификат — трафик можно перехватить.",
        recommendation: "Уберите флаг. Для внутреннего CA установите его сертификат в хранилище доверенных.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::PowerShell],
        pattern: r"-SkipCertificateCheck|ServerCertificateValidationCallback\s*=\s*\{\s*\$true",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
];

pub struct CompiledRule {
    pub index: usize,
    pub regex: Regex,
}

struct LanguageBundle {
    set: RegexSet,
    rules: Vec<CompiledRule>,
}

/// Rules are grouped per language and pre-filtered with a `RegexSet`, so a file
/// only pays for the individual patterns that actually matched somewhere.
static BUNDLES: Lazy<HashMap<Language, LanguageBundle>> = Lazy::new(|| {
    let mut by_lang: HashMap<Language, Vec<usize>> = HashMap::new();
    for (i, rule) in RULES.iter().enumerate() {
        for lang in rule.languages {
            by_lang.entry(*lang).or_default().push(i);
        }
    }

    by_lang
        .into_iter()
        .map(|(lang, indices)| {
            let patterns: Vec<&str> = indices.iter().map(|&i| RULES[i].pattern).collect();
            let set = RegexSet::new(&patterns).unwrap_or_else(|e| {
                panic!("invalid rule pattern for {:?}: {e}", lang);
            });
            let rules = indices
                .iter()
                .map(|&i| CompiledRule {
                    index: i,
                    regex: Regex::new(RULES[i].pattern).expect("pattern already validated"),
                })
                .collect();
            (lang, LanguageBundle { set, rules })
        })
        .collect()
});

pub struct RuleHit {
    pub rule: &'static Rule,
    pub start: usize,
    pub end: usize,
}

fn is_test_path(rel_path: &str) -> bool {
    let p = rel_path.to_ascii_lowercase();
    p.contains("/test")
        || p.starts_with("test")
        || p.contains("/spec")
        || p.contains("__tests__")
        || p.contains("/fixtures/")
        || p.contains("/mocks/")
        || p.ends_with("_test.py")
        || p.ends_with("_test.rs")
        || p.ends_with(".test.js")
        || p.ends_with(".test.ts")
        || p.ends_with(".test.tsx")
        || p.ends_with(".spec.js")
        || p.ends_with(".spec.ts")
        || p.ends_with("conftest.py")
}

/// Exposed so user rules get the same test-path suppression as built-ins.
pub fn path_is_test(rel_path: &str) -> bool {
    is_test_path(rel_path)
}

/// Exposed so user rules skip commented-out code exactly like built-ins do.
pub fn is_comment_line(line: &str, lang: Language) -> bool {
    line_is_comment(line, lang)
}

/// True for lines that are entirely a comment. Cheap approximation: findings in
/// commented-out code are noise, not vulnerabilities.
fn line_is_comment(line: &str, lang: Language) -> bool {
    let t = line.trim_start();
    match lang {
        // Hash-comment family.
        Language::Python
        | Language::Shell
        | Language::PowerShell
        | Language::Perl
        | Language::Ruby
        | Language::Elixir
        | Language::Yaml
        | Language::Kubernetes
        | Language::Dockerfile
        | Language::Terraform
        | Language::Toml
        | Language::Ini
        | Language::Makefile
        | Language::Nginx
        | Language::GraphQL
        | Language::Env => t.starts_with('#'),

        // C-comment family. A leading `*` catches continuation lines of a
        // /* ... */ block, which is where most false positives hide.
        Language::Rust
        | Language::JavaScript
        | Language::TypeScript
        | Language::Jsx
        | Language::Tsx
        | Language::Vue
        | Language::Svelte
        | Language::Go
        | Language::Java
        | Language::Kotlin
        | Language::Scala
        | Language::CSharp
        | Language::C
        | Language::Cpp
        | Language::Swift
        | Language::Php => t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"),

        Language::Sql => t.starts_with("--") || t.starts_with("/*"),
        Language::Lua => t.starts_with("--"),
        Language::Html | Language::Xml => t.starts_with("<!--"),

        _ => false,
    }
}

/// Runs every rule registered for `lang` against `content`.
pub fn scan_content(content: &str, lang: Language, rel_path: &str) -> Vec<RuleHit> {
    let Some(bundle) = BUNDLES.get(&lang) else {
        return Vec::new();
    };

    let matched: Vec<usize> = bundle.set.matches(content).into_iter().collect();
    if matched.is_empty() {
        return Vec::new();
    }

    let in_tests = is_test_path(rel_path);
    let mut hits = Vec::new();

    for local_idx in matched {
        let compiled = &bundle.rules[local_idx];
        let rule = &RULES[compiled.index];

        if in_tests && rule.skip_in_tests {
            continue;
        }

        for m in compiled.regex.find_iter(content) {
            let text = m.as_str();

            // "match X unless Y" — checked against the surrounding line, since the
            // exclusion often sits just outside the match itself.
            let line_start = content[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line_end = content[m.end()..]
                .find('\n')
                .map(|i| m.end() + i)
                .unwrap_or(content.len());
            let line = &content[line_start..line_end];

            if !rule.unless_contains.is_empty() {
                let hay = format!("{} {}", text, line).to_ascii_lowercase();
                if rule
                    .unless_contains
                    .iter()
                    .any(|needle| hay.contains(&needle.to_ascii_lowercase()))
                {
                    continue;
                }
            }

            if line_is_comment(line, lang) {
                continue;
            }

            hits.push(RuleHit {
                rule,
                start: m.start(),
                end: m.end(),
            });
        }
    }

    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit_ids(code: &str, lang: Language, path: &str) -> Vec<&'static str> {
        let mut ids: Vec<&str> = scan_content(code, lang, path)
            .iter()
            .map(|h| h.rule.id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    #[test]
    fn every_rule_pattern_compiles() {
        // Forces the lazy bundles to build; a bad pattern panics here rather
        // than mid-scan in front of a user.
        assert!(!BUNDLES.is_empty());
        for rule in RULES {
            assert!(
                Regex::new(rule.pattern).is_ok(),
                "rule {} has an invalid pattern",
                rule.id
            );
        }
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate rule id");
    }

    #[test]
    fn finds_python_shell_injection() {
        let code = "import subprocess\nsubprocess.run(cmd, shell=True)\n";
        assert!(hit_ids(code, Language::Python, "app.py").contains(&"VS-PY-003"));
    }

    #[test]
    fn finds_python_sql_fstring() {
        let code = "cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n";
        assert!(hit_ids(code, Language::Python, "db.py").contains(&"VS-PY-008"));
    }

    #[test]
    fn yaml_safe_loader_is_not_flagged() {
        let safe = "data = yaml.load(text, Loader=yaml.SafeLoader)\n";
        assert!(!hit_ids(safe, Language::Python, "c.py").contains(&"VS-PY-007"));

        let unsafe_call = "data = yaml.load(text)\n";
        assert!(hit_ids(unsafe_call, Language::Python, "c.py").contains(&"VS-PY-007"));
    }

    #[test]
    fn sanitized_inner_html_is_not_flagged() {
        let safe = "el.innerHTML = DOMPurify.sanitize(userInput);\n";
        assert!(!hit_ids(safe, Language::JavaScript, "a.js").contains(&"VS-JS-004"));

        let unsafe_assign = "el.innerHTML = userInput;\n";
        assert!(hit_ids(unsafe_assign, Language::JavaScript, "a.js").contains(&"VS-JS-004"));
    }

    #[test]
    fn commented_out_code_is_ignored() {
        let code = "# subprocess.run(cmd, shell=True)\n";
        assert!(hit_ids(code, Language::Python, "app.py").is_empty());
    }

    #[test]
    fn noisy_rules_are_suppressed_in_test_files() {
        let code = "x = Math.random()\n";
        assert!(hit_ids(code, Language::JavaScript, "src/app.test.js").is_empty());
        assert!(hit_ids(code, Language::JavaScript, "src/app.js").contains(&"VS-JS-015"));
    }

    #[test]
    fn tsx_inherits_javascript_rules() {
        let code = "<div dangerouslySetInnerHTML={{ __html: bio }} />\n";
        assert!(hit_ids(code, Language::Tsx, "Profile.tsx").contains(&"VS-JS-003"));
    }

    #[test]
    fn finds_rust_tls_bypass() {
        let code = "let c = Client::builder().danger_accept_invalid_certs(true).build()?;\n";
        assert!(hit_ids(code, Language::Rust, "src/net.rs").contains(&"VS-RS-006"));
    }

    #[test]
    fn finds_go_weak_cipher() {
        let code = "block, _ := des.NewCipher(key)\n";
        assert!(hit_ids(code, Language::Go, "crypto.go").contains(&"VS-GO-007"));
    }

    #[test]
    fn finds_go_world_writable() {
        let code = "os.WriteFile(path, data, 0777)\n";
        assert!(hit_ids(code, Language::Go, "io.go").contains(&"VS-GO-009"));
        let ok = "os.WriteFile(path, data, 0600)\n";
        assert!(!hit_ids(ok, Language::Go, "io.go").contains(&"VS-GO-009"));
    }

    #[test]
    fn finds_java_weak_cipher_and_hostname() {
        let cipher = "Cipher c = Cipher.getInstance(\"DES/CBC/PKCS5Padding\");\n";
        assert!(hit_ids(cipher, Language::Java, "Crypto.java").contains(&"VS-JV-007"));
        let host = "conn.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);\n";
        assert!(hit_ids(host, Language::Java, "Net.java").contains(&"VS-JV-008"));
    }

    #[test]
    fn finds_java_cors_wildcard() {
        let code = "config.setAllowedOrigins(Arrays.asList(\"*\"));\n";
        assert!(hit_ids(code, Language::Java, "Cors.java").contains(&"VS-JV-009"));
    }

    #[test]
    fn finds_php_reflected_xss() {
        let code = "<?php echo $_GET['name']; ?>\n";
        assert!(hit_ids(code, Language::Php, "page.php").contains(&"VS-PH-006"));
        let ok = "<?php echo htmlspecialchars($_GET['name'], ENT_QUOTES); ?>\n";
        assert!(!hit_ids(ok, Language::Php, "page.php").contains(&"VS-PH-006"));
    }

    #[test]
    fn finds_php_preg_replace_e() {
        let code = "$out = preg_replace('/(\\w+)/e', 'strtoupper($1)', $in);\n";
        assert!(hit_ids(code, Language::Php, "r.php").contains(&"VS-PH-008"));
        let ok = "$out = preg_replace('/(\\w+)/i', 'X', $in);\n";
        assert!(!hit_ids(ok, Language::Php, "r.php").contains(&"VS-PH-008"));
    }

    #[test]
    fn finds_ruby_send_from_params() {
        let code = "user.send(params[:method])\n";
        assert!(hit_ids(code, Language::Ruby, "app/controllers/u.rb").contains(&"VS-RB-006"));
    }

    #[test]
    fn finds_csharp_weak_tls() {
        let bad = "ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;\n";
        assert!(hit_ids(bad, Language::CSharp, "Net.cs").contains(&"VS-CS-006"));
        let ok = "ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;\n";
        assert!(!hit_ids(ok, Language::CSharp, "Net.cs").contains(&"VS-CS-006"));
    }

    #[test]
    fn finds_csharp_shell_command() {
        let code = "Process.Start(\"cmd.exe\", \"/c \" + userInput);\n";
        assert!(hit_ids(code, Language::CSharp, "Run.cs").contains(&"VS-CS-004"));
    }

    #[test]
    fn finds_c_unbounded_scanf() {
        let code = "char buf[16];\nscanf(\"%s\", buf);\n";
        assert!(hit_ids(code, Language::C, "in.c").contains(&"VS-C-004"));
        let ok = "char buf[16];\nscanf(\"%15s\", buf);\n";
        assert!(!hit_ids(ok, Language::C, "in.c").contains(&"VS-C-004"));
    }

    #[test]
    fn finds_c_insecure_tempfile() {
        let code = "char *p = tmpnam(NULL);\n";
        assert!(hit_ids(code, Language::C, "t.c").contains(&"VS-C-005"));
    }

    #[test]
    fn finds_dockerfile_env_secret() {
        let code = "ENV DB_PASSWORD=hunter2\n";
        assert!(hit_ids(code, Language::Dockerfile, "Dockerfile").contains(&"VS-DK-006"));
        let ok = "ENV APP_PORT=8080\n";
        assert!(!hit_ids(ok, Language::Dockerfile, "Dockerfile").contains(&"VS-DK-006"));
    }

    #[test]
    fn finds_shell_world_writable_chmod() {
        let code = "chmod -R 777 /var/www\n";
        assert!(hit_ids(code, Language::Shell, "deploy.sh").contains(&"VS-SH-002"));
    }

    #[test]
    fn finds_actions_run_injection() {
        let code = "        run: echo \"${{ github.event.issue.title }}\"\n";
        assert!(hit_ids(code, Language::Yaml, ".github/workflows/ci.yml").contains(&"VS-CI-003"));
    }

    #[test]
    fn finds_actions_write_all() {
        let code = "permissions: write-all\n";
        assert!(hit_ids(code, Language::Yaml, ".github/workflows/ci.yml").contains(&"VS-CI-004"));
    }

    #[test]
    fn finds_swift_uiwebview() {
        let code = "let web = UIWebView(frame: .zero)\n";
        assert!(hit_ids(code, Language::Swift, "View.swift").contains(&"VS-SW-001"));
    }

    #[test]
    fn finds_swift_userdefaults_secret() {
        let code = "UserDefaults.standard.set(pw, forKey: \"user_password\")\n";
        assert!(hit_ids(code, Language::Swift, "Auth.swift").contains(&"VS-SW-004"));
        let ok = "UserDefaults.standard.set(theme, forKey: \"app_theme\")\n";
        assert!(!hit_ids(ok, Language::Swift, "Auth.swift").contains(&"VS-SW-004"));
    }

    #[test]
    fn finds_swift_js_injection() {
        let code = "webView.evaluateJavaScript(\"show('\\(name)')\")\n";
        assert!(hit_ids(code, Language::Swift, "Web.swift").contains(&"VS-SW-002"));
    }

    #[test]
    fn finds_nginx_weak_tls() {
        let bad = "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n";
        assert!(hit_ids(bad, Language::Nginx, "nginx.conf").contains(&"VS-NG-002"));
        let ok = "ssl_protocols TLSv1.2 TLSv1.3;\n";
        assert!(!hit_ids(ok, Language::Nginx, "nginx.conf").contains(&"VS-NG-002"));
    }

    #[test]
    fn finds_elixir_binary_to_term() {
        let bad = "term = :erlang.binary_to_term(data)\n";
        assert!(hit_ids(bad, Language::Elixir, "lib/x.ex").contains(&"VS-EX-003"));
        let ok = "term = :erlang.binary_to_term(data, [:safe])\n";
        assert!(!hit_ids(ok, Language::Elixir, "lib/x.ex").contains(&"VS-EX-003"));
    }

    #[test]
    fn finds_perl_two_arg_open() {
        let code = "open(FH, $path) or die;\n";
        assert!(hit_ids(code, Language::Perl, "cgi.pl").contains(&"VS-PL-002"));
    }

    #[test]
    fn finds_scala_sql_interpolation() {
        let code = "val q = s\"SELECT * FROM users WHERE id = $id\"\n";
        assert!(hit_ids(code, Language::Scala, "Repo.scala").contains(&"VS-SC-001"));
    }

    #[test]
    fn finds_lua_os_execute() {
        let code = "os.execute(\"rm \" .. name)\n";
        assert!(hit_ids(code, Language::Lua, "build.lua").contains(&"VS-LU-001"));
    }

    #[test]
    fn finds_python_zip_slip() {
        let code = "tar.extractall(dest)\n";
        assert!(hit_ids(code, Language::Python, "unpack.py").contains(&"VS-PY-022"));
        let ok = "tar.extractall(dest, filter=\"data\")\n";
        assert!(!hit_ids(ok, Language::Python, "unpack.py").contains(&"VS-PY-022"));
    }

    #[test]
    fn finds_python_ssti() {
        let code = "return render_template_string(\"Hello \" + name)\n";
        assert!(hit_ids(code, Language::Python, "views.py").contains(&"VS-PY-023"));
    }

    #[test]
    fn finds_python_jwt_no_verify() {
        let code = "jwt.decode(token, options={\"verify_signature\": False})\n";
        assert!(hit_ids(code, Language::Python, "auth.py").contains(&"VS-PY-024"));
        // A plain requests verify=False must not trip the JWT rule.
        let tls = "requests.get(url, verify=False)\n";
        assert!(!hit_ids(tls, Language::Python, "api.py").contains(&"VS-PY-024"));
    }

    #[test]
    fn finds_js_nosql_where() {
        let code = "db.users.find({ $where: \"this.name == '\" + q + \"'\" })\n";
        assert!(hit_ids(code, Language::JavaScript, "q.js").contains(&"VS-JS-029"));
    }

    #[test]
    fn finds_java_snakeyaml_load() {
        let code = "Object o = new Yaml().load(input);\n";
        assert!(hit_ids(code, Language::Java, "Cfg.java").contains(&"VS-JV-010"));
    }

    #[test]
    fn finds_terraform_public_db() {
        let code = "  publicly_accessible = true\n";
        assert!(hit_ids(code, Language::Terraform, "rds.tf").contains(&"VS-TF-006"));
    }

    #[test]
    fn finds_vue_v_html() {
        let code = "<div v-html=\"userBio\"></div>\n";
        assert!(hit_ids(code, Language::Vue, "Profile.vue").contains(&"VS-VU-001"));
    }

    #[test]
    fn finds_svelte_at_html() {
        let code = "<p>{@html comment}</p>\n";
        assert!(hit_ids(code, Language::Svelte, "Comment.svelte").contains(&"VS-SV-001"));
    }

    #[test]
    fn finds_php_assert_string() {
        let code = "assert(\"$a == $b\");\n";
        assert!(hit_ids(code, Language::Php, "check.php").contains(&"VS-PH-010"));
        // A boolean assert must not trip the string-eval rule.
        let ok = "assert($a === $b);\n";
        assert!(!hit_ids(ok, Language::Php, "check.php").contains(&"VS-PH-010"));
    }

    #[test]
    fn finds_ruby_open_redirect() {
        let code = "redirect_to params[:return_to]\n";
        assert!(hit_ids(code, Language::Ruby, "sessions_controller.rb").contains(&"VS-RB-007"));
    }

    #[test]
    fn finds_go_ssh_ignore_hostkey() {
        let code = "config.HostKeyCallback = ssh.InsecureIgnoreHostKey()\n";
        assert!(hit_ids(code, Language::Go, "ssh.go").contains(&"VS-GO-010"));
    }

    #[test]
    fn finds_csharp_httpclient_cert_bypass() {
        let code = "handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;\n";
        assert!(hit_ids(code, Language::CSharp, "Http.cs").contains(&"VS-CS-007"));
    }

    #[test]
    fn clean_code_produces_no_hits() {
        let code = "fn add(a: u64, b: u64) -> u64 {\n    a + b\n}\n";
        assert!(hit_ids(code, Language::Rust, "src/math.rs").is_empty());
    }
}
