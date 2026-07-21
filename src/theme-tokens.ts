/**
 * The theme contract.
 *
 * Every colour the app paints comes from one of these tokens — nothing is
 * hardcoded in a component — so a theme is just a map of token id → CSS colour.
 * The same map is what the settings editor writes, what `settings.json` stores,
 * and what an exported `.vulnscope-theme.json` carries between machines.
 *
 * Adding a colour to the UI means adding it here first; that is the whole point
 * of the file.
 */

export interface TokenDef {
  /** CSS custom property name without the leading `--`. */
  id: string;
  label: string;
  hint?: string;
}

export interface TokenGroup {
  title: string;
  hint: string;
  tokens: TokenDef[];
}

export const TOKEN_GROUPS: TokenGroup[] = [
  {
    title: "Поверхности",
    hint: "Шкала глубины: каждый шаг — ближе к зрителю. Панели разделяются перепадом, а не линиями.",
    tokens: [
      { id: "s-0", label: "Подложка окна" },
      { id: "s-1", label: "Холст приложения" },
      { id: "s-2", label: "Панели" },
      { id: "s-3", label: "Карточки" },
      { id: "s-4", label: "Контролы" },
      { id: "s-5", label: "Наведение" },
      { id: "line", label: "Тонкая линия" },
      { id: "line-strong", label: "Линия заметная" },
      { id: "scrim", label: "Затемнение под модалкой" },
    ],
  },
  {
    title: "Текст",
    hint: "Иерархия, а не три оттенка серого.",
    tokens: [
      { id: "t-1", label: "Основной" },
      { id: "t-2", label: "Вторичный" },
      { id: "t-3", label: "Третичный" },
      { id: "t-4", label: "Выключенный" },
      { id: "on-a", label: "На акценте", hint: "Текст поверх заливки, не поверх поверхности" },
      { id: "on-a-wash", label: "Плашка на акценте", hint: "Подсказки внутри выделенной строки" },
    ],
  },
  {
    title: "Акцент",
    hint: "Второй акцент — дальний конец градиентов: кольцо прогресса, знак приложения, фон.",
    tokens: [
      { id: "a", label: "Акцент" },
      { id: "a-hi", label: "Акцент светлее" },
      { id: "a-lo", label: "Акцент темнее" },
      { id: "a-ghost", label: "Акцент-подложка" },
      { id: "a-ring", label: "Акцент-обводка" },
      { id: "a2", label: "Второй акцент" },
      { id: "a2-hi", label: "Второй светлее" },
      { id: "a2-ghost", label: "Второй-подложка" },
    ],
  },
  {
    title: "Уровни опасности",
    hint: "Смысловые цвета: их меняют осознанно — на них смотрят, чтобы принять решение.",
    tokens: [
      { id: "crit", label: "Критическая" },
      { id: "crit-hi", label: "Критическая светлее" },
      { id: "crit-bg", label: "Критическая подложка" },
      { id: "crit-ink", label: "Текст на критической" },
      { id: "high", label: "Высокая" },
      { id: "high-hi", label: "Высокая светлее" },
      { id: "high-bg", label: "Высокая подложка" },
      { id: "high-ink", label: "Текст на высокой" },
      { id: "med", label: "Средняя" },
      { id: "med-bg", label: "Средняя подложка" },
      { id: "med-ink", label: "Текст на средней" },
      { id: "low", label: "Низкая" },
      { id: "low-bg", label: "Низкая подложка" },
      { id: "low-ink", label: "Текст на низкой" },
      { id: "info", label: "Информация" },
      { id: "info-bg", label: "Информация подложка" },
      { id: "info-ink", label: "Текст на информации" },
      { id: "ok", label: "Норма" },
      { id: "ok-hi", label: "Норма светлее" },
      { id: "ok-bg", label: "Норма подложка" },
      { id: "danger", label: "Опасное действие" },
    ],
  },
  {
    title: "Подсветка кода",
    hint: "highlight.js переведён на эти токены — иначе светлая схема оставила бы код тёмным.",
    tokens: [
      { id: "syn-text", label: "Обычный текст" },
      { id: "syn-keyword", label: "Ключевые слова" },
      { id: "syn-string", label: "Строки" },
      { id: "syn-number", label: "Числа" },
      { id: "syn-comment", label: "Комментарии" },
      { id: "syn-func", label: "Функции" },
      { id: "syn-type", label: "Типы" },
      { id: "syn-var", label: "Переменные" },
      { id: "syn-attr", label: "Атрибуты" },
      { id: "syn-meta", label: "Мета" },
      { id: "syn-punct", label: "Пунктуация" },
    ],
  },
];

export const ALL_TOKENS: TokenDef[] = TOKEN_GROUPS.flatMap((g) => g.tokens);

export type Theme = Record<string, string>;

export interface Preset {
  id: string;
  label: string;
  hint: string;
  /** Only the tokens that differ from the stylesheet defaults. */
  theme: Theme;
}

/**
 * Surfaces shared by the light schemes, so a new light preset only has to say
 * what makes it different rather than restate an entire palette — and a fix to
 * the light severity colours lands in all of them at once.
 */
const LIGHT_BASE: Theme = {
  scrim: "rgba(20, 24, 33, 0.45)",
  "t-1": "#101521",
  "t-2": "#414b5e",
  "t-3": "#5f6a80",
  "t-4": "#98a2b4",
  crit: "#d32048",
  "crit-hi": "#a3123a",
  "crit-bg": "rgba(211, 32, 72, 0.09)",
  high: "#c2560a",
  "high-hi": "#8f3d05",
  "high-bg": "rgba(194, 86, 10, 0.09)",
  med: "#b08a00",
  "med-bg": "rgba(176, 138, 0, 0.12)",
  low: "#0b6fa4",
  "low-bg": "rgba(11, 111, 164, 0.09)",
  info: "#5b6577",
  "info-bg": "rgba(91, 101, 119, 0.1)",
  ok: "#0f7b46",
  "ok-hi": "#0a5c34",
  "ok-bg": "rgba(15, 123, 70, 0.1)",
  danger: "#c4292e",
  // GitHub Light, so the code viewer follows the rest of the scheme.
  "syn-text": "#24292f",
  "syn-keyword": "#cf222e",
  "syn-string": "#0a3069",
  "syn-number": "#0550ae",
  "syn-comment": "#6e7781",
  "syn-func": "#8250df",
  "syn-type": "#116329",
  "syn-var": "#953800",
  "syn-attr": "#0550ae",
  "syn-meta": "#0550ae",
  "syn-punct": "#24292f",
  "on-a-wash": "rgba(0, 0, 0, 0.14)",
};

/**
 * Presets are diffs, not full themes: "Ночь" is the stylesheet as written, so
 * it is empty. Anything a preset does not name keeps its default, which means
 * adding a token later does not silently break every preset.
 *
 * The dark schemes below mostly restate surfaces and the accent and leave the
 * severity colours alone: those are read to make a decision, and every scheme
 * has to keep them apart — including for colour-blind viewers, which
 * `npm run audit:contrast` checks preset by preset.
 */
export const PRESETS: Preset[] = [
  {
    id: "night",
    label: "Ночь",
    hint: "Как задумано: тёмно-синие поверхности, синий акцент",
    theme: {},
  },
  {
    id: "midnight",
    label: "Полночь",
    hint: "Почти чёрный, для OLED и тёмной комнаты",
    theme: {
      "s-0": "#000000",
      "s-1": "#06070a",
      "s-2": "#0b0d12",
      "s-3": "#101319",
      "s-4": "#171b23",
      "s-5": "#1f242e",
      line: "#151922",
      "line-strong": "#232936",
    },
  },
  {
    id: "day",
    label: "День",
    hint: "Светлая схема целиком, включая подсветку кода",
    theme: {
      ...LIGHT_BASE,
      "s-0": "#e7eaf0",
      "s-1": "#f4f6fa",
      "s-2": "#ffffff",
      "s-3": "#f7f9fc",
      "s-4": "#eef1f6",
      "s-5": "#e4e9f1",
      line: "#dfe4ec",
      "line-strong": "#c6cedb",
      a: "#2563eb",
      "a-hi": "#1d4ed8",
      "a-lo": "#93b4fb",
      "a-ghost": "rgba(37, 99, 235, 0.1)",
      "a-ring": "rgba(37, 99, 235, 0.3)",
      a2: "#7c3aed",
      "a2-hi": "#6d28d9",
      "a2-ghost": "rgba(124, 58, 237, 0.12)",
    },
  },
  {
    id: "contrast",
    label: "Контраст",
    hint: "Максимальная разница: чистый чёрный фон, яркий текст",
    theme: {
      "s-0": "#000000",
      "s-1": "#000000",
      "s-2": "#0a0a0a",
      "s-3": "#141414",
      "s-4": "#1f1f1f",
      "s-5": "#2e2e2e",
      line: "#3a3a3a",
      "line-strong": "#5a5a5a",
      "t-1": "#ffffff",
      "t-2": "#e0e0e0",
      "t-3": "#b8b8b8",
      "t-4": "#8a8a8a",
      a: "#4d9fff",
      "a-hi": "#8cc2ff",
      crit: "#ff6b81",
      high: "#ffa552",
      med: "#ffd76b",
      low: "#6fd3ff",
      ok: "#4ee79a",
      "syn-comment": "#a0a0a0",
    },
  },
  {
    id: "forest",
    label: "Тайга",
    hint: "Тёмная зелень, мягкий изумрудный акцент",
    theme: {
      "s-0": "#060b09",
      "s-1": "#0a1210",
      "s-2": "#0f1a17",
      "s-3": "#14231e",
      "s-4": "#1b2e28",
      "s-5": "#254038",
      line: "#172620",
      "line-strong": "#2c4a41",
      a: "#34d399",
      "a-hi": "#6ee7b7",
      "a-lo": "#116b4d",
      "a-ghost": "rgba(52, 211, 153, 0.12)",
      "a-ring": "rgba(52, 211, 153, 0.32)",
      a2: "#22d3ee",
      "a2-hi": "#67e8f9",
      "a2-ghost": "rgba(34, 211, 238, 0.14)",
    },
  },
  {
    id: "ocean",
    label: "Океан",
    hint: "Глубокая бирюза, холодный бирюзовый акцент",
    theme: {
      "s-0": "#04090f",
      "s-1": "#071219",
      "s-2": "#0b1a24",
      "s-3": "#0f2531",
      "s-4": "#153140",
      "s-5": "#1e4657",
      line: "#132a37",
      "line-strong": "#255064",
      a: "#22d3ee",
      "a-hi": "#67e8f9",
      "a-lo": "#0e7490",
      "a-ghost": "rgba(34, 211, 238, 0.12)",
      "a-ring": "rgba(34, 211, 238, 0.32)",
      a2: "#38bdf8",
      "a2-hi": "#7dd3fc",
      "a2-ghost": "rgba(56, 189, 248, 0.14)",
    },
  },
  {
    id: "amethyst",
    label: "Аметист",
    hint: "Фиолетовые поверхности, сиреневый акцент",
    theme: {
      "s-0": "#08060e",
      "s-1": "#0e0b18",
      "s-2": "#151022",
      "s-3": "#1d162e",
      "s-4": "#271d3d",
      "s-5": "#362a52",
      line: "#211a33",
      "line-strong": "#3d3059",
      a: "#a78bfa",
      "a-hi": "#c4b5fd",
      "a-lo": "#6d28d9",
      "a-ghost": "rgba(167, 139, 250, 0.13)",
      "a-ring": "rgba(167, 139, 250, 0.32)",
      a2: "#f472b6",
      "a2-hi": "#f9a8d4",
      "a2-ghost": "rgba(244, 114, 182, 0.14)",
    },
  },
  {
    id: "graphite",
    label: "Графит",
    hint: "Нейтральный серый без синевы, спокойный акцент",
    theme: {
      "s-0": "#0b0b0c",
      "s-1": "#111112",
      "s-2": "#171719",
      "s-3": "#1d1d20",
      "s-4": "#252528",
      "s-5": "#313135",
      line: "#232326",
      "line-strong": "#3a3a3f",
      "t-1": "#f2f2f3",
      "t-2": "#c6c6ca",
      "t-3": "#97979d",
      "t-4": "#6c6c73",
      a: "#8ab4f8",
      "a-hi": "#aecbfa",
      "a-lo": "#3c5a86",
      "a-ghost": "rgba(138, 180, 248, 0.12)",
      "a-ring": "rgba(138, 180, 248, 0.3)",
      a2: "#c58af9",
      "a2-hi": "#dcb8ff",
      "a2-ghost": "rgba(197, 138, 249, 0.13)",
    },
  },
  {
    id: "paper",
    label: "Бумага",
    hint: "Тёплая светлая: кремовые поверхности, мягкий контраст",
    theme: {
      ...LIGHT_BASE,
      "s-0": "#e6e0d3",
      "s-1": "#f7f3e9",
      "s-2": "#fffdf7",
      "s-3": "#faf6ec",
      "s-4": "#f1ebdd",
      "s-5": "#e7dfcd",
      line: "#e3dccc",
      "line-strong": "#cabfa8",
      "t-1": "#1d1a14",
      "t-2": "#4a443a",
      "t-3": "#6b6355",
      "t-4": "#9b9384",
      a: "#a2570f",
      "a-hi": "#7d420a",
      "a-lo": "#e0b57f",
      "a-ghost": "rgba(162, 87, 15, 0.1)",
      "a-ring": "rgba(162, 87, 15, 0.3)",
      a2: "#0f7b6c",
      "a2-hi": "#0a5c50",
      "a2-ghost": "rgba(15, 123, 108, 0.12)",
      // The cream surface is a shade below pure white, which drops the shared
      // light-theme comment grey under 4.5:1. A notch darker restores it.
      "syn-comment": "#67707a",
    },
  },
  {
    id: "mist",
    label: "Дымка",
    hint: "Светлая холодная: серо-голубые поверхности",
    theme: {
      ...LIGHT_BASE,
      "s-0": "#dde3ea",
      "s-1": "#eef2f7",
      "s-2": "#fbfcfe",
      "s-3": "#f3f6fa",
      "s-4": "#e8edf4",
      "s-5": "#dce3ec",
      line: "#d9e0e9",
      "line-strong": "#bcc7d5",
      a: "#0f766e",
      "a-hi": "#0b574f",
      "a-lo": "#7fcac2",
      "a-ghost": "rgba(15, 118, 110, 0.1)",
      "a-ring": "rgba(15, 118, 110, 0.3)",
      a2: "#4338ca",
      "a2-hi": "#312a9e",
      "a2-ghost": "rgba(67, 56, 202, 0.12)",
      // Same reason as "Бумага": the surface is not pure white.
      "syn-comment": "#67707a",
    },
  },
];

/**
 * Writes a preset plus the user's overrides onto the document.
 *
 * Tokens no longer set by the theme are cleared, not left behind: switching
 * from a light preset back to a dark one has to actually undo the light values,
 * and the stylesheet's own defaults are what should show through.
 */
export function applyTheme(presetId: string | undefined, overrides: Theme | undefined): void {
  captureDefaults();
  const preset = PRESETS.find((p) => p.id === presetId)?.theme ?? {};
  // Inks are derived from the fill they sit on unless spelled out, so picking
  // the green accent cannot leave white text on it.
  const chosen = { ...preset, ...(overrides ?? {}) };
  const merged: Theme = deriveInks({ ...DEFAULTS, ...chosen }, new Set(Object.keys(chosen)));
  const root = document.documentElement;

  for (const { id } of ALL_TOKENS) {
    const v = merged[id];
    if (v && isColor(v)) root.style.setProperty(`--${id}`, v);
    else root.style.removeProperty(`--${id}`);
  }
}

/**
 * The stylesheet's own values, read once before anything overrides them.
 *
 * Reading them on demand does not work: `applyTheme` writes the tokens as
 * inline styles on `:root`, so from that moment `getComputedStyle` returns the
 * *active* value. Asking later for "the default" would hand back whatever the
 * current theme happens to be — which is how the preset previews ended up
 * showing the theme you were already using instead of the one on offer.
 */
let DEFAULTS: Theme | null = null;

function captureDefaults(): void {
  if (DEFAULTS) return;
  const out: Theme = {};

  // Read the `:root` rule out of the stylesheet itself rather than asking for
  // the computed value. Computed values include our own inline overrides, so
  // "the default" would depend on when this first ran — and after a hot reload
  // it captured the active theme and every preset preview became a copy of it.
  for (const sheet of Array.from(document.styleSheets)) {
    let rules: CSSRuleList;
    try {
      rules = sheet.cssRules;
    } catch {
      continue; // cross-origin sheet: not ours, nothing to read
    }
    for (const rule of Array.from(rules)) {
      if (!(rule instanceof CSSStyleRule) || rule.selectorText !== ":root") continue;
      for (const { id } of ALL_TOKENS) {
        const v = rule.style.getPropertyValue(`--${id}`).trim();
        if (v) out[id] = v;
      }
    }
  }

  // Fallback for anything the sheet did not declare.
  const cs = getComputedStyle(document.documentElement);
  for (const { id } of ALL_TOKENS) {
    if (!out[id]) out[id] = cs.getPropertyValue(`--${id}`).trim() || "#000000";
  }
  DEFAULTS = out;
}

/** A token's value as written in theme.css, independent of the active theme. */
export function defaultToken(id: string): string {
  captureDefaults();
  return DEFAULTS?.[id] ?? "#000000";
}

// ------------------------------------------------------------ contrast math

function parseRgb(c: string): [number, number, number] | null {
  const s = c.trim();
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i.exec(s);
  if (hex) {
    let h = hex[1];
    if (h.length === 3 || h.length === 4) h = [...h].map((x) => x + x).join("");
    return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
  }
  const fn = /^rgba?\(([^)]+)\)$/i.exec(s);
  if (fn) {
    const p = fn[1].split(/[,/\s]+/).filter(Boolean).map(Number);
    if (p.length >= 3 && p.every((n) => !Number.isNaN(n))) return [p[0], p[1], p[2]];
  }
  return null;
}

/** WCAG 2.2 relative luminance. */
export function luminance(color: string): number {
  const rgb = parseRgb(color);
  if (!rgb) return 0;
  const f = (v: number) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(rgb[0]) + 0.7152 * f(rgb[1]) + 0.0722 * f(rgb[2]);
}

/** WCAG 2.2 contrast ratio between two opaque colours. */
export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** Near-black rather than pure black: pure black on a coloured fill vibrates. */
const INK_DARK = "#0b0f16";
const INK_LIGHT = "#ffffff";

/**
 * Picks the readable ink for text sitting on `bg`.
 *
 * This has to be computed, not stored: the accent is user-choosable, and white
 * on the green accent measures 1.8:1 — unreadable, and no fixed value can be
 * right for every colour someone might pick.
 */
export function inkFor(bg: string): string {
  return contrast(INK_DARK, bg) >= contrast(INK_LIGHT, bg) ? INK_DARK : INK_LIGHT;
}

/** Fill token → the ink token that must stay legible on it. */
const INK_PAIRS: [string, string][] = [
  ["a", "on-a"],
  ["crit", "crit-ink"],
  ["high", "high-ink"],
  ["med", "med-ink"],
  ["low", "low-ink"],
  ["info", "info-ink"],
];

/**
 * Fills in the ink tokens for any fill nobody chose an ink for.
 *
 * `chosen` is what a preset or the user actually named — those always win. The
 * stylesheet's own value does not count as a choice: it is just the fallback
 * for the shipped accent, and treating it as deliberate is what left white text
 * on every accent someone picked afterwards.
 */
export function deriveInks(theme: Theme, chosen: Set<string> = new Set()): Theme {
  const out = { ...theme };
  for (const [fill, ink] of INK_PAIRS) {
    if (chosen.has(ink) || !out[fill]) continue;
    out[ink] = inkFor(out[fill]);
  }
  return out;
}

/** Accepts the colour syntaxes we can round-trip through a colour input.
 *  Anything else is rejected rather than injected into a style attribute. */
export function isColor(v: string): boolean {
  const s = v.trim();
  if (/^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i.test(s)) return true;
  return /^(rgb|rgba|hsl|hsla)\(\s*[-0-9.,%\s/deg]+\)$/i.test(s);
}
