/**
 * Contrast audit for every shipped theme.
 *
 * Claiming a theme is accessible is easy; this measures it. Ratios follow
 * WCAG 2.2 (relative luminance, 1.4.3 / 1.4.11), and the pairs listed here are
 * the ones the app actually paints — text on the surface it sits on, and UI
 * marks against their background.
 *
 * Run: npm run audit:contrast
 * Exits non-zero if a required pair fails, so it can gate a release.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
// The presets are imported, not parsed: a regex over the source silently
// swallowed one preset and audited another under its name — a check that
// reports on the wrong data is worse than no check.
import { PRESETS, deriveInks } from "../src/theme-tokens.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

// ---------------------------------------------------------------- colour math

function parse(c) {
  const s = c.trim();
  let m = /^#([0-9a-f]{3,8})$/i.exec(s);
  if (m) {
    let h = m[1];
    if (h.length === 3 || h.length === 4) h = [...h].map((x) => x + x).join("");
    return [
      parseInt(h.slice(0, 2), 16),
      parseInt(h.slice(2, 4), 16),
      parseInt(h.slice(4, 6), 16),
      h.length === 8 ? parseInt(h.slice(6, 8), 16) / 255 : 1,
    ];
  }
  m = /^rgba?\(([^)]+)\)$/i.exec(s);
  if (m) {
    const p = m[1].split(/[,/\s]+/).filter(Boolean).map(Number);
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  }
  throw new Error(`не разобрать цвет: ${c}`);
}

/** Alpha colours are what actually reaches the eye once composited. */
function over(fg, bg) {
  const [r, g, b, a] = parse(fg);
  const [br, bg_, bb] = parse(bg);
  return [r * a + br * (1 - a), g * a + bg_ * (1 - a), b * a + bb * (1 - a), 1];
}

function luminance([r, g, b]) {
  const f = (v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

function ratio(fg, bg) {
  const a = luminance(over(fg, bg));
  const b = luminance(parse(bg));
  const [hi, lo] = a > b ? [a, b] : [b, a];
  return (hi + 0.05) / (lo + 0.05);
}

// ------------------------------------------------------- tokens and presets

/** Defaults straight from the stylesheet — the same source the app uses. */
function stylesheetDefaults() {
  const css = readFileSync(join(root, "src/theme.css"), "utf8");
  const out = {};
  for (const m of css.matchAll(/^\s*--([a-z0-9-]+):\s*([^;]+);/gim)) {
    out[m[1]] = m[2].trim();
  }
  return out;
}

// The pairs the interface actually renders. `min` is the WCAG threshold for
// that role: 4.5 for body text, 3 for large text and non-text UI marks.
const PAIRS = [
  { fg: "t-1", bg: "s-1", min: 4.5, what: "основной текст на холсте" },
  { fg: "t-1", bg: "s-2", min: 4.5, what: "основной текст на панели" },
  { fg: "t-1", bg: "s-3", min: 4.5, what: "основной текст на карточке" },
  { fg: "t-2", bg: "s-2", min: 4.5, what: "вторичный текст на панели" },
  { fg: "t-2", bg: "s-3", min: 4.5, what: "вторичный текст на карточке" },
  { fg: "t-3", bg: "s-2", min: 4.5, what: "третичный текст на панели" },
  { fg: "t-3", bg: "s-1", min: 4.5, what: "третичный текст на холсте" },
  { fg: "on-a", bg: "a", min: 4.5, what: "текст на акцентной кнопке" },
  { fg: "a", bg: "s-2", min: 3, what: "акцент как элемент управления" },
  { fg: "crit", bg: "s-2", min: 3, what: "критическая на панели" },
  { fg: "crit", bg: "s-1", min: 3, what: "критическая на холсте" },
  { fg: "high", bg: "s-2", min: 3, what: "высокая на панели" },
  { fg: "med", bg: "s-2", min: 3, what: "средняя на панели" },
  { fg: "low", bg: "s-2", min: 3, what: "низкая на панели" },
  { fg: "info", bg: "s-2", min: 3, what: "информация на панели" },
  { fg: "ok", bg: "s-2", min: 3, what: "норма на панели" },
  { fg: "crit-ink", bg: "crit", min: 4.5, what: "число на критическом бейдже" },
  { fg: "high-ink", bg: "high", min: 4.5, what: "число на высоком бейдже" },
  { fg: "med-ink", bg: "med", min: 4.5, what: "число на среднем бейдже" },
  { fg: "low-ink", bg: "low", min: 4.5, what: "число на низком бейдже" },
  { fg: "info-ink", bg: "info", min: 4.5, what: "число на инфо-бейдже" },
  { fg: "syn-text", bg: "s-2", min: 4.5, what: "код: обычный текст" },
  { fg: "syn-keyword", bg: "s-2", min: 4.5, what: "код: ключевые слова" },
  { fg: "syn-string", bg: "s-2", min: 4.5, what: "код: строки" },
  { fg: "syn-comment", bg: "s-2", min: 4.5, what: "код: комментарии" },
  { fg: "syn-func", bg: "s-2", min: 4.5, what: "код: функции" },
  { fg: "syn-type", bg: "s-2", min: 4.5, what: "код: типы" },
  { fg: "syn-var", bg: "s-2", min: 4.5, what: "код: переменные" },
  { fg: "syn-number", bg: "s-2", min: 4.5, what: "код: числа" },
];

const defaults = stylesheetDefaults();
let failures = 0;

for (const p of PRESETS) {
  // Same resolution the app performs, derived inks included — auditing the
  // raw preset would check colours the user never sees.
  const t = deriveInks({ ...defaults, ...p.theme }, new Set(Object.keys(p.theme)));
  const bad = [];
  for (const pair of PAIRS) {
    const fg = t[pair.fg];
    const bg = t[pair.bg];
    if (!fg || !bg) {
      bad.push(`  ? ${pair.what}: нет токена ${!fg ? pair.fg : pair.bg}`);
      continue;
    }
    const r = ratio(fg, bg);
    if (r < pair.min) {
      bad.push(
        `  ✗ ${pair.what.padEnd(34)} ${r.toFixed(2)} : 1  (нужно ${pair.min}) — --${pair.fg} на --${pair.bg}`
      );
    }
  }
  failures += bad.length;
  const mark = bad.length === 0 ? "✓" : "✗";
  console.log(`\n${mark} ${p.label} (${p.id}): проверено ${PAIRS.length} пар, провалено ${bad.length}`);
  bad.forEach((b) => console.log(b));
}

console.log(
  failures === 0
    ? "\nВсе схемы проходят пороги WCAG 2.2 AA."
    : `\nВсего нарушений: ${failures}`
);

// ------------------------------------------------- colour-vision deficiency

/**
 * Severity is the one thing in this app people act on, and it is carried by
 * colour. WCAG 1.4.1 says colour must never be the only cue — every severity
 * also has its own icon — but the palette should still hold up on its own.
 *
 * Simulation matrices: Viénot, Brettel & Mollon (1999), linear-RGB space.
 */
const CVD = {
  "протанопия (нет красных)": [
    [0.1121, 0.8853, -0.0005], [0.1127, 0.8897, -0.0001], [0.0045, 0.0, 1.0],
  ],
  "дейтеранопия (нет зелёных)": [
    [0.292, 0.7054, -0.0003], [0.2934, 0.7089, 0.0], [-0.0195, 0.0333, 1.0],
  ],
  "тританопия (нет синих)": [
    [1.0, 0.1502, -0.1387], [0.0, 0.8493, 0.1462], [0.0, 0.2704, 0.7291],
  ],
};

const toLin = (v) => { const c = v / 255; return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
const toSrgb = (c) => { const v = c <= 0.0031308 ? c * 12.92 : 1.055 * c ** (1 / 2.4) - 0.055; return Math.min(255, Math.max(0, v * 255)); };

function simulate(hex, m) {
  const [r, g, b] = parse(hex).slice(0, 3).map(toLin);
  return [0, 1, 2].map((i) => toSrgb(m[i][0] * r + m[i][1] * g + m[i][2] * b));
}

/** Perceptual-ish distance; good enough to catch "these two now look alike". */
function distance(a, b) {
  const [dr, dg, db] = [0, 1, 2].map((i) => a[i] - b[i]);
  const rm = (a[0] + b[0]) / 2;
  return Math.sqrt((2 + rm / 256) * dr * dr + 4 * dg * dg + (2 + (255 - rm) / 256) * db * db);
}

const SEV = ["crit", "high", "med", "low", "info"];
const MIN_DISTANCE = 40; // below this two severities read as the same colour

console.log("\n--- Различимость уровней опасности при ЦВД -------------------");
let cvdWarnings = 0;
for (const p of PRESETS) {
  const t = deriveInks({ ...defaults, ...p.theme }, new Set(Object.keys(p.theme)));
  const problems = [];
  for (const [name, m] of Object.entries(CVD)) {
    const sim = Object.fromEntries(SEV.map((s) => [s, simulate(t[s], m)]));
    for (let i = 0; i < SEV.length; i++) {
      for (let j = i + 1; j < SEV.length; j++) {
        const d = distance(sim[SEV[i]], sim[SEV[j]]);
        if (d < MIN_DISTANCE) problems.push(`  ! ${name}: ${SEV[i]} и ${SEV[j]} сливаются (${d.toFixed(0)})`);
      }
    }
  }
  cvdWarnings += problems.length;
  console.log(`${problems.length ? "!" : "✓"} ${p.label}: спорных пар ${problems.length}`);
  problems.forEach((x) => console.log(x));
}
console.log(
  cvdWarnings === 0
    ? "Уровни различимы при всех трёх типах ЦВД (плюс у каждого свой значок)."
    : `Пар, различимых только по цвету: ${cvdWarnings} — их спасает значок уровня.`
);

process.exit(failures === 0 ? 0 : 1);
