/**
 * Settings audit — the class of bug where a control is saved, drawn, and obeyed
 * by nobody.
 *
 * A field on `Settings` serialises, renders as a toggle with a helpful hint, and
 * persists to `settings.json` whether or not a single line of code ever reads
 * it. Nothing complains: serde counts the field as "used", `tsc` sees a valid
 * property, and the switch animates. On 25.07.2026 four of them had been living
 * like that — `skipNoisyInTests`, `ignoreComments`, `osvCacheDays`,
 * `osvConcurrency`; the last two even had constants beside them holding exactly
 * the default the setting claimed to control. Flipping any of them changed
 * nothing, which is worse than the feature being absent.
 *
 * Three things are checked, each of which was a real defect or a live drift
 * risk rather than a hypothetical:
 *
 * 1. **Dead settings.** Every field of the Rust `Settings` struct must be read
 *    by something — Rust outside `settings.rs`, or the frontend. A field nobody
 *    reads is a lie told to the user.
 * 2. **Shape drift.** Rust `Settings` and the TypeScript `AppSettings` must
 *    describe the same set of fields. A field on one side only is a setting the
 *    UI cannot show, or one the UI shows and the backend discards on save.
 * 3. **Export-id drift.** The list of export formats exists in three places —
 *    `EXPORT_FORMATS` (validation, Rust), `EXPORT_CHOICES` (the picker) and
 *    `EXPORTERS` (what Ctrl+S dispatches to). If they disagree, the user picks a
 *    format that is silently rejected on save, or one that maps to no exporter.
 *
 * The check is deliberately textual. Reading is the point: a field mentioned in
 * a comment counts, because a human wrote the name down for a reason and the
 * alternative — parsing Rust — buys precision this does not need.
 *
 * Usage: npm run audit:settings
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname, basename } from "node:path";

const ROOT = new URL("../", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const RUST = join(ROOT, "src-tauri", "src");
const SRC = join(ROOT, "src");

function walk(dir, exts) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p, exts));
    else if (exts.includes(extname(name))) out.push(p);
  }
  return out;
}

const snakeToCamel = (s) => s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());

/** Field names of `pub struct Settings`. */
function rustSettingsFields() {
  const src = readFileSync(join(RUST, "settings.rs"), "utf8");
  const body = src.match(/pub struct Settings \{([\s\S]*?)\n\}/);
  if (!body) throw new Error("не найден pub struct Settings в settings.rs");
  return [...body[1].matchAll(/\n {4}pub (\w+):/g)].map((m) => m[1]);
}

/** Field names of `interface AppSettings`. */
function tsSettingsFields() {
  const src = readFileSync(join(SRC, "types.ts"), "utf8");
  const body = src.match(/export interface AppSettings \{([\s\S]*?)\n\}/);
  if (!body) throw new Error("не найден interface AppSettings в types.ts");
  // Strip comments so a field name mentioned in prose is not counted twice.
  const clean = body[1]
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "");
  return [...clean.matchAll(/\n {2}(\w+)[?]?:/g)].map((m) => m[1]);
}

/** Comma-separated string literals inside a named Rust const array. */
function rustStringList(file, name) {
  const src = readFileSync(join(RUST, file), "utf8");
  const m = src.match(new RegExp(`const ${name}[^=]*=\\s*&\\[([\\s\\S]*?)\\];`));
  if (!m) throw new Error(`не найден ${name} в ${file}`);
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
}

// --------------------------------------------------------------- 1. dead ones

const rustFields = rustSettingsFields();
const tsFields = tsSettingsFields();

/**
 * Rust that consumes settings, as opposed to declaring them.
 *
 * `settings.rs` is excluded — a field is obviously mentioned by its own struct,
 * its Default, and `sanitize` — except for the `impl Settings` accessor block.
 * Accessors like `rule_behavior()` and `blame_budget()` are how a field reaches
 * the scanner without the scanner naming it, so ignoring them would report a
 * live setting as dead. (A field used only inside an accessor nobody calls would
 * slip through; the block is a dozen lines and read on every change.)
 */
const settingsRs = readFileSync(join(RUST, "settings.rs"), "utf8");
const accessors = settingsRs.match(/\nimpl Settings \{[\s\S]*?\n\}/)?.[0] ?? "";

const rustBlob = [
  ...walk(RUST, [".rs"])
    .filter((f) => basename(f) !== "settings.rs")
    .map((f) => readFileSync(f, "utf8")),
  accessors,
].join("\n");

/**
 * Files that *edit* settings rather than act on them.
 *
 * This exclusion is the whole check. Counting the settings screen as a reader is
 * what would let the original four through: every dead setting had a beautifully
 * rendered toggle in `Settings.tsx` and no consumer anywhere. Drawing a control
 * for a value is not the same as doing something with it.
 */
const EDITORS_NOT_READERS = new Set(["Settings.tsx", "types.ts", "demo.ts", "i18n.tsx"]);

const consumerBlob = walk(SRC, [".ts", ".tsx"])
  .filter((f) => !EDITORS_NOT_READERS.has(basename(f)))
  .map((f) => readFileSync(f, "utf8"))
  .join("\n");

// Plenty of settings are legitimately frontend-only — theme, density, the a11y
// switches, the code viewer — so "read by the scanner" is the wrong bar. The bar
// is that somebody acts on the value.
const dead = rustFields.filter((field) => {
  const camel = snakeToCamel(field);
  const inRust = rustBlob.includes(field);
  const inFront = new RegExp(`[.{,\\s]${camel}\\b`).test(consumerBlob);
  return !inRust && !inFront;
});

// ------------------------------------------------------------- 2. shape drift

const rustCamel = new Set(rustFields.map(snakeToCamel));
const tsSet = new Set(tsFields);
const onlyRust = [...rustCamel].filter((f) => !tsSet.has(f));
const onlyTs = [...tsSet].filter((f) => !rustCamel.has(f));

// ------------------------------------------------------------ 3. export ids

const rustFormats = rustStringList("settings.rs", "EXPORT_FORMATS");

const settingsTsx = readFileSync(join(SRC, "Settings.tsx"), "utf8");
const choicesBlock = settingsTsx.match(/const EXPORT_CHOICES[^=]*=\s*\[([\s\S]*?)\n\];/);
const choiceIds = choicesBlock
  ? [...choicesBlock[1].matchAll(/\[\s*"([^"]+)"/g)].map((m) => m[1])
  : null;

const appTsx = readFileSync(join(SRC, "App.tsx"), "utf8");
// Not `[^=]*` before the `=`: the type annotation is `Record<string, () => void>`
// and the arrow's `=` would end the match early.
const exportersBlock = appTsx.match(/const EXPORTERS\b[\s\S]*?=\s*\{([\s\S]*?)\n\s*\};/);
const exporterIds = exportersBlock
  ? [...exportersBlock[1].matchAll(/\n\s{4}(\w+):/g)].map((m) => m[1])
  : null;

const setEq = (a, b) => a.length === b.length && a.every((x) => b.includes(x));
const exportProblems = [];
if (!choiceIds) exportProblems.push("не найден EXPORT_CHOICES в Settings.tsx");
if (!exporterIds) exportProblems.push("не найден EXPORTERS в App.tsx");
if (choiceIds && !setEq(rustFormats, choiceIds)) {
  exportProblems.push(
    `EXPORT_FORMATS (Rust) ≠ EXPORT_CHOICES (Settings.tsx): [${rustFormats}] против [${choiceIds}]`
  );
}
if (exporterIds && !setEq(rustFormats, exporterIds)) {
  exportProblems.push(
    `EXPORT_FORMATS (Rust) ≠ EXPORTERS (App.tsx): [${rustFormats}] против [${exporterIds}]`
  );
}

// ----------------------------------------------------------------- report

console.log(`Полей в Settings: ${rustFields.length}`);

console.log(
  dead.length === 0
    ? "✓ Каждую настройку кто-то читает."
    : `✗ Настройки, которые не читает никто: ${dead.length}`
);
for (const f of dead) console.log(`    ${f}`);

console.log(
  onlyRust.length === 0 && onlyTs.length === 0
    ? "✓ Settings (Rust) и AppSettings (TS) описывают одно и то же."
    : "✗ Наборы полей разошлись"
);
for (const f of onlyRust) console.log(`    только в Rust: ${f}`);
for (const f of onlyTs) console.log(`    только в TS:   ${f}`);

console.log(
  exportProblems.length === 0
    ? `✓ Список форматов экспорта совпадает во всех трёх местах (${rustFormats.length}).`
    : "✗ Списки форматов экспорта разошлись"
);
for (const p of exportProblems) console.log(`    ${p}`);

if (dead.length === 0 && onlyRust.length === 0 && onlyTs.length === 0 && exportProblems.length === 0) {
  process.exit(0);
}

if (dead.length) {
  console.log(
    "\nПоле сериализуется и рисуется независимо от того, читает ли его хоть кто-то: переключатель будет работать, а поведение не изменится. Проведите значение до кода — или уберите настройку."
  );
}
if (onlyRust.length || onlyTs.length) {
  console.log(
    "\nПоле только в Rust интерфейс не покажет; поле только в TS бэкенд отбросит при сохранении (serde игнорирует лишние ключи)."
  );
}
if (exportProblems.length) {
  console.log(
    "\nИдентификаторы форматов живут в трёх местах: sanitize отвергнет неизвестный, меню не найдёт экспортёр. Держите списки в согласии."
  );
}
process.exit(1);
