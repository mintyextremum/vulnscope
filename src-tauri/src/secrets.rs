use crate::model::{Confidence, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// A hardcoded-credential detector. Provider-specific patterns are precise
/// enough to report on their own; the generic ones additionally require the
/// captured value to look random (see `shannon_entropy`).
pub struct SecretRule {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub pattern: &'static str,
    /// Index of the capture group holding the secret itself (0 = whole match).
    pub value_group: usize,
    /// Minimum Shannon entropy (bits/char) for the captured value. 0.0 disables.
    pub min_entropy: f64,
    pub cwe: &'static [&'static str],
}

pub static SECRET_RULES: &[SecretRule] = &[
    SecretRule {
        id: "VS-SEC-001",
        title: "AWS Access Key ID в коде",
        description: "Идентификатор ключа AWS зашит в исходник. В паре с секретным ключом он даёт полный доступ к аккаунту AWS в рамках прав этого ключа.",
        recommendation: "Немедленно отзовите ключ в IAM — он скомпрометирован фактом попадания в репозиторий. Используйте IAM-роли или переменные окружения. Историю git тоже нужно вычистить (git filter-repo).",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-002",
        title: "AWS Secret Access Key в коде",
        description: "Секретный ключ AWS в исходнике. Вместе с Access Key ID позволяет управлять инфраструктурой и данными аккаунта.",
        recommendation: "Отзовите ключ в IAM прямо сейчас. Перейдите на IAM-роли (для EC2/ECS/Lambda) или на временные учётные данные STS.",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
        pattern: r#"(?i)aws[_-]?(?:secret|sec)[_-]?(?:access)?[_-]?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
        value_group: 1,
        min_entropy: 4.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-003",
        title: "GitHub Personal Access Token",
        description: "Токен GitHub даёт доступ к репозиториям владельца в объёме своих scope: чтение приватного кода, пуш, а иногда управление организацией.",
        recommendation: "Отзовите токен в Settings → Developer settings → Personal access tokens. Для CI используйте GITHUB_TOKEN или GitHub App с минимальными правами.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-004",
        title: "Приватный криптографический ключ",
        description: "В файле лежит приватный ключ (RSA/EC/OpenSSH/PGP). Он позволяет расшифровать трафик, подделать подпись или зайти на сервер по SSH.",
        recommendation: "Считайте ключ скомпрометированным: сгенерируйте новый и отзовите старый. Приватные ключи не хранят в репозитории — используйте секрет-хранилище (Vault, KMS, SOPS).",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"-----BEGIN\s+(?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        value_group: 0,
        min_entropy: 0.0,
        cwe: &["CWE-798", "CWE-321"],
    },
    SecretRule {
        id: "VS-SEC-005",
        title: "Slack-токен",
        description: "Токен Slack позволяет читать историю каналов и отправлять сообщения от имени бота или пользователя.",
        recommendation: "Отзовите токен в настройках приложения Slack и выпустите новый. Храните его в переменных окружения.",
        severity: Severity::High,
        confidence: Confidence::High,
        pattern: r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-006",
        title: "Stripe API-ключ",
        description: "Живой секретный ключ Stripe даёт доступ к платёжным операциям и данным клиентов.",
        recommendation: "Отзовите ключ в дашборде Stripe (Developers → API keys) и выпустите новый. Секретный ключ должен быть только на сервере.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-007",
        title: "Google API-ключ",
        description: "Ключ Google API в коде. Без ограничений по домену/IP им может воспользоваться кто угодно — вплоть до исчерпания вашей квоты и счёта.",
        recommendation: "Отзовите ключ в Google Cloud Console и выпустите новый с ограничениями по HTTP-referrer или IP.",
        severity: Severity::High,
        confidence: Confidence::High,
        pattern: r"\b(AIza[0-9A-Za-z_-]{35})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-008",
        title: "Строка подключения к БД с паролем",
        description: "URI содержит логин и пароль к базе данных. Если сервис доступен по сети, это прямой путь к данным.",
        recommendation: "Вынесите строку подключения в переменную окружения. Пароль в репозитории считайте скомпрометированным и смените.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:@\s/]+:([^@\s/]{4,})@",
        value_group: 1,
        min_entropy: 2.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-009",
        title: "Токен Telegram-бота",
        description: "Токен даёт полный контроль над ботом: чтение сообщений и отправка от его имени.",
        recommendation: "Отзовите токен через @BotFather (/revoke) и получите новый. Храните в переменной окружения.",
        severity: Severity::High,
        confidence: Confidence::High,
        pattern: r"\b([0-9]{8,10}:AA[0-9A-Za-z_-]{33})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-010",
        title: "OpenAI / Anthropic API-ключ",
        description: "Ключ доступа к платному LLM-API. Утечка означает списания с вашего счёта и доступ к вашим данным в сервисе.",
        recommendation: "Отзовите ключ в кабинете провайдера и выпустите новый. Ключ должен жить в переменной окружения на сервере, а не в клиентском коде.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b(sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,})\b",
        value_group: 1,
        min_entropy: 3.5,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-011",
        title: "Пароль зашит в код",
        description: "Пароль в исходнике виден всем, у кого есть доступ к репозиторию, и остаётся в истории git даже после удаления строки.",
        recommendation: "Вынесите в переменную окружения или секрет-хранилище. Смените сам пароль — он уже скомпрометирован.",
        severity: Severity::High,
        confidence: Confidence::Low,
        pattern: r#"(?i)\b(?:password|passwd|pwd|senha|contrasena)\s*[:=]\s*["']([^"'\s]{8,})["']"#,
        value_group: 1,
        min_entropy: 3.0,
        cwe: &["CWE-798", "CWE-259"],
    },
    SecretRule {
        id: "VS-SEC-012",
        title: "Обобщённый API-ключ или токен в коде",
        description: "Значение выглядит как реальный ключ доступа: достаточно длинное и с высокой энтропией.",
        recommendation: "Перенесите в переменную окружения или секрет-хранилище и отзовите текущее значение.",
        severity: Severity::High,
        confidence: Confidence::Low,
        pattern: r#"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|private[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-/+=.]{20,})["']"#,
        value_group: 1,
        min_entropy: 3.8,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-013",
        title: "JWT с полезной нагрузкой в коде",
        description: "В исходнике лежит готовый JWT. Если он ещё не истёк, им можно воспользоваться напрямую; заодно он раскрывает структуру ваших claim'ов.",
        recommendation: "Уберите токен из кода. Если он рабочий — отзовите и смените ключ подписи.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        pattern: r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-014",
        title: "GitLab Personal Access Token",
        description: "Токен GitLab даёт доступ к репозиториям и API в объёме своих scope: чтение приватного кода, пуш, управление проектами и CI/CD.",
        recommendation: "Отзовите токен в GitLab (User Settings → Access Tokens) и выпустите новый. Для CI используйте CI/CD-переменные с маскированием.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b(glpat-[0-9A-Za-z_-]{20})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-015",
        title: "npm-токен доступа",
        description: "Токен npm позволяет публиковать пакеты от вашего имени и читать приватные. Утечка ведёт к компрометации цепочки поставок.",
        recommendation: "Отзовите токен на npmjs.com (Access Tokens) и выпустите новый. Храните его в CI-секретах, а не в .npmrc в репозитории.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b(npm_[0-9A-Za-z]{36})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-016",
        title: "SendGrid API-ключ",
        description: "Ключ SendGrid позволяет отправлять почту от вашего домена — вектор фишинга и порчи репутации отправителя.",
        recommendation: "Отзовите ключ в панели SendGrid (Settings → API Keys) и выпустите новый с минимальными правами.",
        severity: Severity::High,
        confidence: Confidence::High,
        pattern: r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-017",
        title: "Shopify Access Token",
        description: "Токен доступа Shopify даёт доступ к данным магазина: заказам, клиентам и настройкам через Admin API.",
        recommendation: "Отзовите токен в админке Shopify (Apps → Develop apps) и выпустите новый. Храните его на сервере, а не в клиенте.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b(shp(?:at|ss|ca|pa)_[0-9a-fA-F]{32})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-018",
        title: "DigitalOcean Personal Access Token",
        description: "Токен DigitalOcean управляет вашей инфраструктурой через API: дроплетами, базами, DNS и биллингом.",
        recommendation: "Отзовите токен в панели DigitalOcean (API → Tokens) и выпустите новый. Храните в переменных окружения.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b(dop_v1_[0-9a-f]{64})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-019",
        title: "Токен загрузки PyPI",
        description: "Токен PyPI позволяет публиковать пакеты от вашего имени. Утечка ведёт к компрометации цепочки поставок Python.",
        recommendation: "Отзовите токен на pypi.org (Account settings → API tokens) и выпустите новый с областью на конкретный проект.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b(pypi-AgEIcHlwaS[A-Za-z0-9_-]{50,})",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-020",
        title: "Ключ доступа Azure Storage",
        description: "AccountKey в строке подключения Azure Storage даёт полный доступ к аккаунту хранилища: чтение, запись и удаление всех блобов, очередей и таблиц.",
        recommendation: "Смените ключ (rotate) в портале Azure и перейдите на SAS-токены с ограниченными правами или на управляемые удостоверения.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"AccountKey=([A-Za-z0-9+/=]{86,88})",
        value_group: 1,
        min_entropy: 4.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-021",
        title: "Twilio API Key",
        description: "SID API-ключа Twilio вместе с секретом даёт доступ к отправке SMS и звонков за ваш счёт и к данным сообщений.",
        recommendation: "Отзовите ключ в консоли Twilio и выпустите новый. Храните секрет вне кода.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        pattern: r"\b(SK[0-9a-f]{32})\b",
        value_group: 1,
        min_entropy: 3.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-022",
        title: "Mailgun API-ключ",
        description: "Ключ Mailgun позволяет отправлять письма от имени ваших доменов и читать логи доставки. Утечка ведёт к рассылке спама и фишинга с вашей репутацией.",
        recommendation: "Смените ключ в панели Mailgun (Settings → API Keys). Держите его в переменных окружения.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        pattern: r"\b(key-[0-9a-f]{32})\b",
        value_group: 1,
        min_entropy: 3.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-023",
        title: "Токен Discord-бота",
        description: "Токен бота Discord даёт полный контроль над ботом: чтение сообщений, действия на серверах, где он состоит.",
        recommendation: "Сбросьте токен в Developer Portal (Bot → Reset Token). Храните его в секрет-хранилище.",
        severity: Severity::High,
        confidence: Confidence::High,
        pattern: r"\b([MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-024",
        title: "Токен доступа Square",
        description: "Токен Square даёт доступ к платежам, транзакциям и данным клиентов вашего аккаунта.",
        recommendation: "Отзовите токен в Square Developer Dashboard и выпустите новый. Секрет держите на сервере.",
        severity: Severity::Critical,
        confidence: Confidence::High,
        pattern: r"\b(sq0(?:atp|csp)-[0-9A-Za-z_-]{22,43})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-025",
        title: "Токен Hugging Face",
        description: "Токен Hugging Face даёт доступ к приватным моделям и датасетам и позволяет публиковать от вашего имени.",
        recommendation: "Отзовите токен в настройках Hugging Face (Access Tokens) и выпустите новый с минимальными правами.",
        severity: Severity::High,
        confidence: Confidence::High,
        pattern: r"\b(hf_[A-Za-z0-9]{34,})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-026",
        title: "Postman API-ключ",
        description: "Ключ Postman API даёт доступ к вашим коллекциям, окружениям и секретам, хранящимся в них.",
        recommendation: "Отзовите ключ в настройках Postman (API keys) и выпустите новый.",
        severity: Severity::High,
        confidence: Confidence::High,
        pattern: r"\b(PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-027",
        title: "Токен Databricks",
        description: "Персональный токен Databricks даёт доступ к рабочим областям, кластерам и данным через API.",
        recommendation: "Отзовите токен в User Settings → Access Tokens и выпустите новый с ограниченным сроком.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        pattern: r"\b(dapi[0-9a-f]{32})\b",
        value_group: 1,
        min_entropy: 3.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-028",
        title: "New Relic API-ключ",
        description: "Ключ New Relic API даёт доступ к телеметрии, дашбордам и настройкам мониторинга вашего аккаунта.",
        recommendation: "Отзовите ключ в New Relic (API keys) и выпустите новый.",
        severity: Severity::High,
        confidence: Confidence::High,
        pattern: r"\b(NRAK-[A-Z0-9]{27})\b",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-029",
        title: "Токен интеграции Notion",
        description: "Токен интеграции Notion даёт доступ к страницам и базам, к которым подключена интеграция.",
        recommendation: "Отзовите токен в настройках интеграции Notion и выпустите новый.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        pattern: r"\b(secret_[A-Za-z0-9]{43})\b",
        value_group: 1,
        min_entropy: 4.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-030",
        title: "Sentry DSN с секретным ключом",
        description: "DSN Sentry с секретной частью позволяет отправлять и, в старом формате, читать события проекта. Он раскрывает адрес и идентификатор проекта.",
        recommendation: "Используйте публичный DSN (без секретной части) и держите его в переменных окружения, а не в клиентском коде.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        pattern: r"(https://[0-9a-f]{32}@[a-zA-Z0-9.-]+/[0-9]+)",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
    SecretRule {
        id: "VS-SEC-031",
        title: "Slack Incoming Webhook",
        description: "URL входящего вебхука Slack позволяет любому отправлять сообщения в привязанный канал. Это удобный вектор для фишинга внутри рабочего пространства.",
        recommendation: "Отзовите вебхук в настройках приложения Slack и выпустите новый. URL держите в секрет-хранилище.",
        severity: Severity::High,
        confidence: Confidence::High,
        pattern: r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24})",
        value_group: 1,
        min_entropy: 0.0,
        cwe: &["CWE-798"],
    },
];

/// Substrings that mark a value as a placeholder rather than a live credential.
const PLACEHOLDERS: &[&str] = &[
    "your", "example", "placeholder", "changeme", "change_me", "dummy", "sample", "test",
    "xxxxx", "aaaaa", "12345", "insert", "replace", "todo", "fixme", "foobar", "<your",
    "here", "myapp", "redacted", "removed", "secret_key_here", "notreal", "fake", "mock",
    "abcdef", "000000", "lorem", "n/a", "none", "null", "undefined", "process.env",
    "os.environ", "getenv", "${", "{{", "%s", "..." ,
];

/// Shannon entropy in bits per character. Random tokens land around 4-6;
/// English words and repeated characters land well below 3.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_like_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if PLACEHOLDERS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // A value made of one or two distinct characters is filler, not a key.
    let distinct: HashSet<u8> = value.bytes().collect();
    distinct.len() <= 2
}

static COMPILED: Lazy<Vec<Regex>> = Lazy::new(|| {
    SECRET_RULES
        .iter()
        .map(|r| Regex::new(r.pattern).unwrap_or_else(|e| panic!("bad secret pattern {}: {e}", r.id)))
        .collect()
});

pub struct SecretHit {
    pub rule: &'static SecretRule,
    /// Byte span of the whole match, used to locate the finding.
    pub start: usize,
    pub end: usize,
    /// Byte span of the secret value itself, so callers can redact exactly it
    /// and nothing else.
    pub value_start: usize,
    pub value_end: usize,
    /// Masked form of the value, safe to show in the UI and in exported reports.
    pub masked: String,
}

/// Keeps a short prefix so the user can recognise which key it is, and hides the rest.
fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{}{}{}", head, "*".repeat(chars.len().min(24) - 6), tail)
}

pub fn scan_secrets(content: &str, rel_path: &str) -> Vec<SecretHit> {
    // Lockfiles are full of high-entropy integrity hashes that are not secrets.
    let lower = rel_path.to_ascii_lowercase();
    if lower.ends_with("lock.json")
        || lower.ends_with(".lock")
        || lower.ends_with("yarn.lock")
        || lower.ends_with("pnpm-lock.yaml")
    {
        return Vec::new();
    }

    let mut hits = Vec::new();

    for (i, rule) in SECRET_RULES.iter().enumerate() {
        for caps in COMPILED[i].captures_iter(content) {
            let Some(m) = caps.get(rule.value_group).or_else(|| caps.get(0)) else {
                continue;
            };
            let value = m.as_str();

            if looks_like_placeholder(value) {
                continue;
            }
            if rule.min_entropy > 0.0 && shannon_entropy(value) < rule.min_entropy {
                continue;
            }

            let whole = caps.get(0).map(|w| (w.start(), w.end())).unwrap_or((m.start(), m.end()));
            hits.push(SecretHit {
                rule,
                start: whole.0,
                end: whole.1,
                value_start: m.start(),
                value_end: m.end(),
                masked: mask(value),
            });
        }
    }

    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(code: &str, path: &str) -> Vec<&'static str> {
        scan_secrets(code, path).iter().map(|h| h.rule.id).collect()
    }

    #[test]
    fn every_secret_pattern_compiles() {
        assert_eq!(COMPILED.len(), SECRET_RULES.len());
    }

    #[test]
    fn entropy_separates_random_from_words() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0);
        assert!(shannon_entropy("password") < 3.5);
        assert!(shannon_entropy("kJ82mNp4Qr7sTv1wXy3zAb6cDe9fGh0i") > 4.0);
    }

    #[test]
    fn finds_aws_access_key() {
        assert!(ids("key = \"AKIAQYZ4W7RJ2NBKV6LC\"", "c.py").contains(&"VS-SEC-001"));
    }

    #[test]
    fn aws_documentation_key_is_treated_as_placeholder() {
        // The canonical key from AWS docs is fake; flagging it would be noise.
        assert!(ids("key = \"AKIAIOSFODNN7EXAMPLE\"", "c.py").is_empty());
    }

    #[test]
    fn finds_github_token() {
        let code = "token = \"ghp_kJ8m2NpQ4rT7sV1wXy3zAb6cDe9fGh0iJk2L\"";
        assert!(ids(code, "c.py").contains(&"VS-SEC-003"));
    }

    #[test]
    fn finds_private_key_block() {
        assert!(ids("-----BEGIN RSA PRIVATE KEY-----", "id_rsa").contains(&"VS-SEC-004"));
    }

    #[test]
    fn finds_gitlab_and_npm_tokens() {
        assert!(ids("t = \"glpat-aB3dE6fH9jK2mN5pQ8rT\"", "c.rb").contains(&"VS-SEC-014"));
        let npm = "//registry.npmjs.org/:_authToken=npm_aB3dE6fH9jK2mN5pQ8rT4vW7xY0zC1dF2gH5";
        assert!(ids(npm, ".npmrc").contains(&"VS-SEC-015"));
    }

    #[test]
    fn finds_shopify_and_digitalocean_tokens() {
        assert!(ids("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", "app.rb").contains(&"VS-SEC-017"));
        let dop = "token = \"dop_v1_deadbeefcafebabefeedfacedeadc0dedeadbeefcafebabefeedfacedeadc0de\"";
        assert!(ids(dop, "main.go").contains(&"VS-SEC-018"));
    }

    #[test]
    fn finds_more_provider_tokens() {
        let azure = "conn = \"DefaultEndpointsProtocol=https;AccountKey=aZ3k9Qw2eR7tyU1ioP4asD6fgH8jkL0zxC5vbN2mqW9erT3yuI7opA1sdF6ghJ8klZ0xcV4bnM2qwE9rtY3uiO==\"";
        assert!(ids(azure, "cfg.cs").contains(&"VS-SEC-020"));
        assert!(ids("key = \"hf_kR9mZ2qW7xL4nP8vT1yB6cJ3dH5gF0sAeUoI\"", "m.py").contains(&"VS-SEC-025"));
        assert!(ids("nr = \"NRAK-K9MZ2QW7XL4NP8VT1YB6CJ3DH5G\"", "c.js").contains(&"VS-SEC-028"));
        let hook = "url = \"https://hooks.slack.com/services/T9K2QW7X/B4NP8VT1Y/kR9mZ2qWxL4nP8vT1yB6cJ3d\"";
        assert!(ids(hook, "n.py").contains(&"VS-SEC-031"));
    }

    #[test]
    fn ignores_placeholder_values() {
        assert!(ids("api_key = \"your-api-key-here-replace\"", "c.py").is_empty());
        assert!(ids("password = \"changeme123\"", "c.py").is_empty());
        assert!(ids("api_key = \"xxxxxxxxxxxxxxxxxxxxxxxx\"", "c.py").is_empty());
    }

    #[test]
    fn ignores_env_var_indirection() {
        assert!(ids("api_key = os.environ[\"REAL_API_KEY_NAME\"]", "c.py").is_empty());
        assert!(ids("apiKey = process.env.SOME_LONG_KEY_NAME", "c.js").is_empty());
    }

    #[test]
    fn ignores_low_entropy_generic_values() {
        // Long but obviously not a key.
        assert!(ids("api_key = \"aaaaaaaaaaaaaaaaaaaaaaaaaa\"", "c.py").is_empty());
    }

    #[test]
    fn finds_high_entropy_generic_key() {
        let code = "api_key = \"kJ8m2NpQ4rT7sV1wXy3zAb6cDe9fGh0i\"";
        assert!(ids(code, "c.py").contains(&"VS-SEC-012"));
    }

    #[test]
    fn skips_lockfiles_entirely() {
        let code = "\"integrity\": \"sha512-kJ8m2NpQ4rT7sV1wXy3zAb6cDe9fGh0iJkLmNoPqRsTu\"";
        assert!(ids(code, "package-lock.json").is_empty());
    }

    #[test]
    fn masks_value_without_revealing_it() {
        let hits = scan_secrets("key = \"AKIAIOSFODNN7EXAMPLE\"", "c.py");
        // "EXAMPLE" makes this a placeholder, so use a realistic-looking one instead.
        assert!(hits.is_empty());

        let hits = scan_secrets("token = \"ghp_kJ8m2NpQ4rT7sV1wXy3zAb6cDe9fGh0iJk2L\"", "c.py");
        let h = &hits[0];
        assert!(h.masked.starts_with("ghp_"));
        assert!(h.masked.contains('*'));
        assert!(!h.masked.contains("kJ8m2NpQ4rT7sV1wXy3zAb6cDe9fGh0iJk2L"));
    }

    #[test]
    fn finds_db_connection_string() {
        let code = "DATABASE_URL = \"postgresql://admin:kJ8m2NpQ4rT@db.internal:5432/prod\"";
        assert!(ids(code, "settings.py").contains(&"VS-SEC-008"));
    }
}
