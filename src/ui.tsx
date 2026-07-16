import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Icon } from "./components";
import { useT } from "./i18n";

// ------------------------------------------------------------- resizable

/**
 * A draggable divider that resizes the panel to its left.
 *
 * The width lives in localStorage: a layout the user adjusted should still be
 * there next launch, otherwise the adjustment feels ignored.
 */
export function Resizer({
  width,
  setWidth,
  min = 180,
  max = 560,
  storageKey,
}: {
  width: number;
  setWidth: (w: number) => void;
  min?: number;
  max?: number;
  storageKey: string;
}) {
  const [dragging, setDragging] = useState(false);
  const startX = useRef(0);
  const startW = useRef(0);

  const onDown = (e: React.PointerEvent) => {
    e.preventDefault();
    startX.current = e.clientX;
    startW.current = width;
    setDragging(true);
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  };

  const onMove = (e: React.PointerEvent) => {
    if (!dragging) return;
    const next = Math.min(max, Math.max(min, startW.current + (e.clientX - startX.current)));
    setWidth(next);
  };

  const onUp = (e: React.PointerEvent) => {
    if (!dragging) return;
    setDragging(false);
    (e.target as HTMLElement).releasePointerCapture(e.pointerId);
    try {
      localStorage.setItem(storageKey, String(width));
    } catch {
      // Storage can be unavailable; the layout simply resets next launch.
    }
  };

  // Keyboard resize keeps the divider reachable without a pointer.
  const onKey = (e: React.KeyboardEvent) => {
    const step = e.shiftKey ? 40 : 12;
    if (e.key === "ArrowLeft") {
      e.preventDefault();
      setWidth(Math.max(min, width - step));
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      setWidth(Math.min(max, width + step));
    } else {
      return;
    }
    try {
      localStorage.setItem(storageKey, String(width));
    } catch {
      /* ignore */
    }
  };

  return (
    <div
      className={`resizer ${dragging ? "dragging" : ""}`}
      onPointerDown={onDown}
      onPointerMove={onMove}
      onPointerUp={onUp}
      onPointerCancel={onUp}
      onKeyDown={onKey}
      role="separator"
      aria-orientation="vertical"
      aria-valuenow={width}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      title="Потяните, чтобы изменить ширину"
    >
      <div className="resizer-grip" />
    </div>
  );
}

export function useStoredWidth(key: string, fallback: number): [number, (w: number) => void] {
  const [width, setWidth] = useState(() => {
    try {
      const raw = localStorage.getItem(key);
      const n = raw ? parseInt(raw, 10) : NaN;
      return Number.isFinite(n) ? n : fallback;
    } catch {
      return fallback;
    }
  });
  return [width, setWidth];
}

// --------------------------------------------------------- virtualisation

export interface VirtualWindow {
  /** First index to render, including overscan. */
  start: number;
  /** One past the last index to render. */
  end: number;
  /** Height of the full list, so the scrollbar is honest. */
  totalHeight: number;
  /** Pixel offset of `start`, used to position the rendered slice. */
  offsetY: number;
}

/**
 * Computes which rows of a uniform-height list are worth rendering.
 *
 * Without this the code viewer builds one DOM node per line: `typescript.js` in
 * a node_modules tree is ~200k lines, which freezes the window outright. Rows
 * are a fixed height because the viewer is monospace, so the maths stays exact
 * and no measurement pass is needed.
 */
export function useVirtual(
  ref: React.RefObject<HTMLElement | null>,
  count: number,
  rowHeight: number,
  overscan = 12
): VirtualWindow {
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(0);

  // `count` is in the deps on purpose. The scroll container often does not
  // exist on first render — the code viewer shows a loading state until the
  // file arrives — and a ref object never changes identity, so an effect keyed
  // only on `ref` would attach nothing and never re-run. Rendering then breaks
  // silently: the list scrolls but no rows appear.
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;

    const onScroll = () => setScrollTop(el.scrollTop);
    // Passive: this listener never calls preventDefault, and saying so lets the
    // browser scroll without waiting on us.
    el.addEventListener("scroll", onScroll, { passive: true });

    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    ro.observe(el);
    setHeight(el.clientHeight);
    setScrollTop(el.scrollTop);

    return () => {
      el.removeEventListener("scroll", onScroll);
      ro.disconnect();
    };
  }, [ref, count]);

  return useMemo(() => {
    const visible = Math.ceil(height / rowHeight) + overscan * 2;
    const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
    const end = Math.min(count, start + visible);
    return {
      start,
      end,
      totalHeight: count * rowHeight,
      offsetY: start * rowHeight,
    };
  }, [scrollTop, height, count, rowHeight, overscan]);
}

// ---------------------------------------------------------- transitions

/**
 * Cross-fades between screens. Children are keyed by `view`; when it changes the
 * old node fades out and the new one fades in, so navigation reads as one
 * surface changing rather than a hard cut.
 */
export function ViewTransition({
  view,
  children,
}: {
  view: string;
  children: React.ReactNode;
}) {
  const [rendered, setRendered] = useState(children);
  const [current, setCurrent] = useState(view);
  const [phase, setPhase] = useState<"in" | "out">("in");

  useLayoutEffect(() => {
    if (view === current) {
      setRendered(children);
      return;
    }
    setPhase("out");
    const t = setTimeout(() => {
      setCurrent(view);
      setRendered(children);
      setPhase("in");
    }, 130);
    return () => clearTimeout(t);
  }, [view, children, current]);

  return <div className={`view view-${phase}`}>{rendered}</div>;
}

// ------------------------------------------------------- command palette

export interface Command {
  id: string;
  label: string;
  hint?: string;
  icon: string;
  keys?: string;
  run: () => void;
  /** Hidden when false; lets callers offer only what applies right now. */
  when?: boolean;
}

export function CommandPalette({
  open,
  onClose,
  commands,
}: {
  open: boolean;
  onClose: () => void;
  commands: Command[];
}) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const available = useMemo(() => commands.filter((c) => c.when !== false), [commands]);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return available;
    return available.filter(
      (c) =>
        c.label.toLowerCase().includes(q) || (c.hint ?? "").toLowerCase().includes(q)
    );
  }, [available, query]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setIndex(0);
      // Focus after paint, or the input is not in the DOM yet.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => setIndex(0), [query]);

  useEffect(() => {
    listRef.current
      ?.querySelector<HTMLElement>(`[data-idx="${index}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [index]);

  if (!open) return null;

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown" || (e.ctrlKey && e.key === "n")) {
      e.preventDefault();
      setIndex((i) => Math.min(results.length - 1, i + 1));
    } else if (e.key === "ArrowUp" || (e.ctrlKey && e.key === "p")) {
      e.preventDefault();
      setIndex((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const cmd = results[index];
      if (cmd) {
        onClose();
        cmd.run();
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  return (
    <div className="palette-backdrop" onClick={onClose}>
      <div className="palette" onClick={(e) => e.stopPropagation()} onKeyDown={onKey}>
        <div className="palette-input">
          <Icon name="search" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("Команда или действие…")}
            aria-label="Поиск команды"
          />
          <kbd>Esc</kbd>
        </div>
        <div className="palette-list" ref={listRef}>
          {results.length === 0 && <div className="palette-empty">{t("Ничего не найдено")}</div>}
          {results.map((c, i) => (
            <button
              key={c.id}
              data-idx={i}
              className={`palette-item ${i === index ? "active" : ""}`}
              onMouseEnter={() => setIndex(i)}
              onClick={() => {
                onClose();
                c.run();
              }}
            >
              <Icon name={c.icon} />
              <span className="pi-label">{c.label}</span>
              {c.hint && <span className="pi-hint">{c.hint}</span>}
              {c.keys && <kbd>{c.keys}</kbd>}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// -------------------------------------------------------------- hotkeys

/** True when focus is in a field, so shortcuts must not steal the keystroke. */
function inEditable(t: EventTarget | null): boolean {
  const el = t as HTMLElement | null;
  if (!el) return false;
  const tag = el.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
}

export function useHotkeys(
  map: Record<string, (e: KeyboardEvent) => void>,
  deps: unknown[] = []
) {
  const handler = useCallback(
    (e: KeyboardEvent) => {
      const parts: string[] = [];
      if (e.ctrlKey || e.metaKey) parts.push("mod");
      if (e.shiftKey) parts.push("shift");
      if (e.altKey) parts.push("alt");
      parts.push(e.key.toLowerCase());
      const combo = parts.join("+");

      const fn = map[combo];
      if (!fn) return;

      // Plain keys stay usable while typing; modifier combos still fire.
      const isPlain = !e.ctrlKey && !e.metaKey && !e.altKey;
      if (isPlain && inEditable(e.target) && e.key !== "Escape") return;

      fn(e);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    deps
  );

  useEffect(() => {
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [handler]);
}

// --------------------------------------------------------------- shells

/** Placeholder rows shown while a panel's data loads. */
export function Skeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="skeleton">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="sk-row" style={{ animationDelay: `${i * 60}ms` }}>
          <div className="sk-bar" style={{ width: `${55 + ((i * 13) % 35)}%` }} />
          <div className="sk-bar sk-sub" style={{ width: `${25 + ((i * 7) % 20)}%` }} />
        </div>
      ))}
    </div>
  );
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}
