/**
 * Localization completeness audit.
 *
 * Every user-visible string is keyed by its Russian source in the `EN`
 * dictionary (src/i18n.tsx). A missing key does not fail loudly — `translate`
 * falls back to the source, so the English UI silently shows Russian. That is
 * invisible in review and only surfaces if someone switches the language, which
 * is exactly why it needs a check of its own.
 *
 * Two sources feed the UI, so both are checked:
 *
 *  1. Shell strings — literal `t(...)`/`tr(...)` arguments across `src/`.
 *  2. The rule catalogue — title/description/recommendation/category on every
 *     `Rule` in rules.rs and every `SecretRule` in secrets.rs. These are Rust
 *     constants rendered through `t(finding.title)` and friends, so a new rule
 *     without a dictionary entry shows up in Russian for English users.
 *
 * Not covered: labels built at runtime (OSV messages with `{}` placeholders) and
 * the assorted `*Label` mappings in the scanner — those are not parseable from a
 * literal and would false-positive here.
 *
 * Usage: npm run audit:i18n
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const ROOT = new URL("../", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const SRC = join(ROOT, "src");
const DICT_FILE = join(SRC, "i18n.tsx");
const RULES_FILE = join(ROOT, "src-tauri", "src", "rules.rs");
const SECRETS_FILE = join(ROOT, "src-tauri", "src", "secrets.rs");
const MODEL_FILE = join(ROOT, "src-tauri", "src", "model.rs");

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if ([".ts", ".tsx"].includes(extname(name))) out.push(p);
  }
  return out;
}

/** Unescapes a JS/Rust string literal body. */
function unesc(s) {
  return s.replace(/\\(["'\\])/g, "$1").replace(/\\n/g, "\n");
}

/** Adds `key` to the map, recording where it came from. */
function add(map, key, where) {
  if (!key) return;
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(where);
}

/** Literal keys passed to t(...) / tr(...) across the frontend. */
function shellKeys(files) {
  const keys = new Map();
  const re = /(?<![\w.])tr?\(\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')/g;
  for (const f of files) {
    for (const m of readFileSync(f, "utf8").matchAll(re)) {
      const raw = m[1] ?? m[2];
      if (raw === undefined) continue;
      add(keys, unesc(raw), f.slice(SRC.length + 1));
    }
  }
  return keys;
}

function field(block, name) {
  const m = block.match(new RegExp(name + '\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"'));
  return m ? unesc(m[1]) : null;
}

/**
 * Translatable strings on each rule struct. `splitOn` is the struct literal that
 * opens an entry; the `pub struct` definition has no `id`, so it drops out.
 */
function catalogueKeys(file, splitOn, fields, label) {
  const keys = new Map();
  const src = readFileSync(file, "utf8");
  for (const block of src.split(splitOn)) {
    const id = block.match(/id\s*:\s*"([^"]+)"/);
    if (!id || !id[1].startsWith("VS-")) continue;
    for (const f of fields) add(keys, field(block, f), `${label} ${id[1]}`);
  }
  return keys;
}

/** The body of `impl <name> { … }`, found by matching braces from its opening. */
function implBlock(src, name) {
  const start = src.indexOf(`impl ${name} {`);
  if (start < 0) return "";
  let depth = 0;
  for (let i = src.indexOf("{", start); i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1);
  }
  return src.slice(start);
}

/**
 * Labels the backend attaches to a finding, a skipped file or a scan phase.
 * They are `match` arms on an enum rather than struct fields, and they reach the
 * UI as `sourceLabel` / `reasonLabel` / `phaseLabel` — rendered through `t(...)`
 * like the catalogue, so they need dictionary entries just the same.
 */
function labelKeys(file, enums) {
  const keys = new Map();
  const src = readFileSync(file, "utf8");
  for (const name of enums) {
    for (const m of implBlock(src, name).matchAll(/=>\s*"((?:[^"\\]|\\.)*)"/g)) {
      add(keys, unesc(m[1]), name);
    }
  }
  return keys;
}

/**
 * Re-escapes a runtime string into the form it is written as inside a source
 * literal delimited by `q`, so it can be matched against the dictionary text.
 * Without this a key containing a newline is searched for as a real line break
 * while the file spells it `\n`, and a key containing a quote never matches.
 */
function toSourceLiteral(s, q) {
  return s
    .replace(/\\/g, "\\\\")
    .replace(new RegExp(q, "g"), "\\" + q)
    .replace(/\n/g, "\\n");
}

const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * True when the dictionary declares `key`. An entry is written in whichever
 * quote keeps it readable — "Файл": "File", but 'scanf("%s")…' switches to
 * single quotes because the key itself contains double ones — and short keys may
 * be bare identifiers (Подавленные: "Suppressed"). All three forms count.
 */
function dictHas(dict, key) {
  for (const q of ['"', "'"]) {
    const lit = reEscape(toSourceLiteral(key, q));
    if (new RegExp("\\n\\s*" + q + lit + q + "\\s*:").test(dict)) return true;
  }
  if (/^[\p{L}_$][\p{L}\p{N}_$]*$/u.test(key)) {
    if (new RegExp("\\n\\s*" + reEscape(key) + "\\s*:").test(dict)) return true;
  }
  return false;
}

/**
 * The dictionary is keyed by the Russian source, so a string with no Cyrillic in
 * it — a rule id, a code fragment, an English term like "Path traversal" — needs
 * no entry: falling back to the source already yields the right English.
 */
const needsTranslation = (s) => /[Ѐ-ӿ]/.test(s);

const dict = readFileSync(DICT_FILE, "utf8");

const groups = [
  {
    name: "Оболочка (t(...) в src/)",
    keys: shellKeys(walk(SRC).filter((f) => !f.endsWith("i18n.tsx") && !f.endsWith("demo.ts"))),
  },
  {
    name: "Каталог правил (rules.rs)",
    keys: catalogueKeys(RULES_FILE, "Rule {", ["title", "description", "recommendation", "category"], "правило"),
  },
  {
    name: "Детекторы секретов (secrets.rs)",
    keys: catalogueKeys(SECRETS_FILE, "SecretRule {", ["title", "description", "recommendation"], "секрет"),
  },
  {
    name: "Метки времени выполнения (model.rs)",
    keys: labelKeys(MODEL_FILE, ["FindingSource", "SkipReason", "ScanPhase"]),
  },
];

let failed = 0;
for (const g of groups) {
  const checked = [...g.keys.entries()].filter(([k]) => needsTranslation(k));
  const missing = checked.filter(([k]) => !dictHas(dict, k));
  const mark = missing.length === 0 ? "✓" : "✗";
  const skipped = g.keys.size - checked.length;
  console.log(
    `${mark} ${g.name}: ${checked.length - missing.length}/${checked.length}` +
      (skipped ? ` (${skipped} без кириллицы — перевод не нужен)` : "")
  );
  for (const [k, where] of missing) {
    console.log(`    ${JSON.stringify(k.length > 66 ? k.slice(0, 66) + "…" : k)}`);
    console.log(`        ${[...where].slice(0, 4).join(", ")}`);
  }
  failed += missing.length;
}

if (failed === 0) {
  console.log("\nВсе строки есть в словаре EN — фоллбэков на русский нет.");
  process.exit(0);
}
console.log(`\nБез перевода: ${failed}. В EN-режиме покажутся по-русски — добавьте в словарь EN (src/i18n.tsx).`);
process.exit(1);
