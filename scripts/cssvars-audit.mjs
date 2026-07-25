/**
 * Stylesheet hygiene audit — two failures that are invisible until someone
 * notices the screen looks slightly wrong.
 *
 * 1. Undeclared design tokens (below).
 * 2. Literal colours in the component sheet: a colour written past the tokens is
 *    a colour the ten themes and the user's own edits never reach. Deliberate
 *    exceptions — the `@media print` paper palette and `var(--x, …)` fallbacks —
 *    are excluded by construction, not by eye.
 *
 * A misspelled token does not fail loudly — `color: var(--surface-2)` with no
 * such property makes the *whole declaration* invalid and the browser drops it
 * silently. The element keeps its inherited value and looks almost right, so
 * nothing in review, in `tsc`, or in the build says a word. Every instance of
 * this in the project so far was found by eye, late, and by luck.
 *
 * Checked: every `var(--x)` in the stylesheets must resolve to a property that
 * is declared somewhere — in `theme.css`, in `App.css` (a rule may define a
 * local token, e.g. `.tone-crit { --tone: … }`), in the token catalogue that the
 * theme editor writes at runtime, or in a React inline style.
 *
 * A usage that supplies a fallback (`var(--shadow-lg, 0 8px 30px …)`) is fine by
 * construction and is not reported: the fallback is what an undeclared token is
 * for.
 *
 * Usage: npm run audit:cssvars
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname, basename } from "node:path";

const ROOT = new URL("../", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const SRC = join(ROOT, "src");
const CSS_FILES = ["theme.css", "App.css"].map((f) => join(SRC, f));

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if ([".ts", ".tsx"].includes(extname(name))) out.push(p);
  }
  return out;
}

/** Custom properties declared in a stylesheet: `--name:` at a declaration site. */
function declaredInCss(text) {
  const names = new Set();
  for (const m of text.matchAll(/(?:^|[{;])\s*(--[a-z][a-z0-9-]*)\s*:/gim)) {
    names.add(m[1]);
  }
  return names;
}

/**
 * Properties the app defines at runtime: the theme editor writes every token id
 * from the catalogue onto `:root`, and components set one-off tokens through
 * inline styles (`style={{ "--tone": … }}`).
 */
function declaredInCode(files) {
  const names = new Set();
  for (const f of files) {
    const src = readFileSync(f, "utf8");
    for (const m of src.matchAll(/["'](--[a-z][a-z0-9-]*)["']\s*:/g)) names.add(m[1]);
    // theme-tokens.ts: setProperty(`--${id}`, …) over a catalogue of ids.
    if (basename(f) === "theme-tokens.ts") {
      for (const m of src.matchAll(/\bid:\s*"([a-z][a-z0-9-]*)"/g)) names.add("--" + m[1]);
    }
  }
  return names;
}

/** Every `var(--x)` without a fallback, with the line it sits on. */
function usages(file) {
  const out = [];
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, i) => {
    for (const m of line.matchAll(/var\(\s*(--[a-z][a-z0-9-]*)\s*(,?)/g)) {
      if (m[2] === ",") continue; // has a fallback — safe by construction
      out.push({ name: m[1], file: basename(file), line: i + 1, text: line.trim() });
    }
  });
  return out;
}

/** Text with every balanced `@media print { … }` block removed. */
function withoutPrintBlocks(text) {
  let out = "";
  let i = 0;
  for (;;) {
    const at = text.indexOf("@media print", i);
    if (at < 0) return out + text.slice(i);
    out += text.slice(i, at);
    let depth = 0;
    let p = text.indexOf("{", at);
    for (; p < text.length; p++) {
      if (text[p] === "{") depth++;
      else if (text[p] === "}" && --depth === 0) break;
    }
    i = p + 1;
  }
}

/** Text with every balanced `var( … )` expression removed. */
function withoutVarCalls(text) {
  let out = "";
  let i = 0;
  for (;;) {
    const at = text.indexOf("var(", i);
    if (at < 0) return out + text.slice(i);
    out += text.slice(i, at);
    let depth = 0;
    let p = at + 3;
    for (; p < text.length; p++) {
      if (text[p] === "(") depth++;
      else if (text[p] === ")" && --depth === 0) break;
    }
    i = p + 1;
  }
}

/**
 * Literal colours in the component stylesheet.
 *
 * Every colour the UI shows must come from a token, or the ten themes and the
 * user's own edits stop reaching part of the screen. Two exceptions are real and
 * deliberate, so they are excluded rather than tolerated by eye:
 *
 *  - `@media print` — paper has no theme. A dark-theme token printed on white is
 *    the bug, so the print block carries its own literal paper palette.
 *  - fallbacks inside `var(--x, …)` — the fallback exists precisely to be a
 *    literal when the token is absent.
 */
function literalColours(file) {
  const text = withoutVarCalls(withoutPrintBlocks(readFileSync(file, "utf8")));
  const hits = [];
  for (const m of text.matchAll(/#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?)\(/g)) {
    hits.push({ value: m[0], line: text.slice(0, m.index).split("\n").length });
  }
  return hits;
}

const declared = new Set();
for (const f of CSS_FILES) for (const n of declaredInCss(readFileSync(f, "utf8"))) declared.add(n);
for (const n of declaredInCode(walk(SRC))) declared.add(n);

const missing = [];
for (const f of CSS_FILES) {
  for (const u of usages(f)) if (!declared.has(u.name)) missing.push(u);
}

// theme.css is where colours are *defined*; only the component sheet is checked.
const literals = literalColours(join(SRC, "App.css"));

console.log(`Объявлено токенов: ${declared.size}`);
console.log(
  missing.length === 0
    ? "✓ Все var(--…) без запасного значения ссылаются на объявленные токены."
    : `✗ Необъявленные токены: ${missing.length}`
);
for (const m of missing) {
  console.log(`    ${m.name} — ${m.file}:${m.line}`);
  console.log(`        ${m.text.length > 90 ? m.text.slice(0, 90) + "…" : m.text}`);
}

console.log(
  literals.length === 0
    ? "✓ Цвета в App.css только из токенов (кроме @media print и фоллбэков)."
    : `✗ Литеральные цвета вне @media print: ${literals.length}`
);
for (const l of literals) console.log(`    ${l.value} — App.css:${l.line}`);

if (missing.length === 0 && literals.length === 0) process.exit(0);

if (missing.length) {
  console.log(
    "\nБраузер молча выбрасывает всё правило с несуществующим токеном. Объявите его в theme.css или задайте запасное значение: var(--имя, значение)."
  );
}
if (literals.length) {
  console.log(
    "\nЦвет мимо токена не подхватят ни темы, ни правки пользователя. Возьмите токен из theme.css (для печати цвет литералом — норма, но только внутри @media print)."
  );
}
process.exit(1);
