/**
 * Localization completeness audit.
 *
 * Every user-visible string is wrapped in `t("...")`, and the English dictionary
 * in src/i18n.tsx is keyed by the Russian source. A key that is missing from the
 * dictionary does not fail loudly — `translate` falls back to the source, so the
 * English UI silently shows Russian. That is invisible in review and only shows
 * up if someone actually switches the language, which is exactly why it needs a
 * check that runs on its own.
 *
 * This walks the frontend for literal `t(...)`/`tr(...)` arguments and reports
 * the ones the dictionary has no entry for. Non-literal calls — `t(f.title)`,
 * `t(SEVERITY_LABEL[s])` — carry backend content and are checked separately.
 *
 * Usage: npm run audit:i18n
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const SRC = new URL("../src/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const DICT_FILE = join(SRC, "i18n.tsx");

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if ([".ts", ".tsx"].includes(extname(name))) out.push(p);
  }
  return out;
}

/** Unescapes a JS string literal body. */
function unesc(s) {
  return s.replace(/\\(["'\\])/g, "$1").replace(/\\n/g, "\n");
}

/** Literal keys passed to t(...) / tr(...) across the frontend. */
function usedKeys(files) {
  const keys = new Map(); // key -> Set(file)
  const re = /(?<![\w.])tr?\(\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')/g;
  for (const f of files) {
    const src = readFileSync(f, "utf8");
    for (const m of src.matchAll(re)) {
      const raw = m[1] ?? m[2];
      if (raw === undefined || raw === "") continue;
      const key = unesc(raw);
      if (!keys.has(key)) keys.set(key, new Set());
      keys.get(key).add(f.slice(SRC.length));
    }
  }
  return keys;
}

/**
 * Re-escapes a runtime string back into the form it is written as in source, so
 * it can be matched against the dictionary text. Without this a key containing a
 * newline is searched for as a real line break while the file spells it `\n`.
 */
function toSourceLiteral(s) {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * True when the dictionary declares `key`. Entries appear either quoted
 * ("Файл": "File") or as a bare identifier (Подавленные: "Suppressed"), so both
 * forms have to be accepted.
 */
function dictHas(dict, key) {
  const quoted = reEscape(toSourceLiteral(key));
  if (new RegExp('\\n\\s*"' + quoted + '"\\s*:').test(dict)) return true;
  // Bare identifier keys: only possible when the key is a valid identifier.
  if (/^[\p{L}_$][\p{L}\p{N}_$]*$/u.test(key)) {
    if (new RegExp("\\n\\s*" + reEscape(key) + "\\s*:").test(dict)) return true;
  }
  return false;
}

const dict = readFileSync(DICT_FILE, "utf8");
const files = walk(SRC).filter((f) => !f.endsWith("i18n.tsx") && !f.endsWith("demo.ts"));
const used = usedKeys(files);

const missing = [...used.entries()].filter(([k]) => !dictHas(dict, k));

console.log(`Строк в коде через t(): ${used.size}`);
if (missing.length === 0) {
  console.log("✓ Все строки интерфейса есть в словаре EN — фоллбэков на русский нет.");
  process.exit(0);
}

console.log(`\n✗ Нет в словаре EN: ${missing.length}\n`);
for (const [k, where] of missing) {
  console.log(`  ${JSON.stringify(k.length > 70 ? k.slice(0, 70) + "…" : k)}`);
  console.log(`      ${[...where].join(", ")}`);
}
console.log("\nВ EN-режиме эти строки покажутся по-русски. Добавьте их в словарь EN (src/i18n.tsx).");
process.exit(1);
