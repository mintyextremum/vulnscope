import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Icon } from "./components";
import { useT } from "./i18n";

/**
 * Replaces the OS title bar so the window is one continuous surface.
 *
 * The whole strip is a drag region except for interactive children, which opt
 * out via `data-tauri-drag-region` being absent — otherwise a click on a button
 * starts a window drag instead of firing onClick.
 */
export function Titlebar({ children }: { children?: React.ReactNode }) {
  const t = useT();
  const [maximized, setMaximized] = useState(false);
  const win = getCurrentWindow();

  useEffect(() => {
    let alive = true;
    win.isMaximized().then((m) => alive && setMaximized(m));
    // The window can also be maximized by dragging to the top edge or by the
    // OS shortcut, so poll the real state rather than trusting our own clicks.
    const unlisten = win.onResized(() => {
      win.isMaximized().then((m) => alive && setMaximized(m));
    });
    return () => {
      alive = false;
      unlisten.then((f) => f());
    };
  }, [win]);

  return (
    <div className="titlebar" data-tauri-drag-region>
      <div className="tb-brand" data-tauri-drag-region>
        <div className="tb-mark">
          <Icon name="shield_lock" />
        </div>
        <span className="tb-name" data-tauri-drag-region>
          VulnScope
        </span>
      </div>

      {/* The empty space around the actions is the main place a user grabs to
          move the window, so it must be a drag region too. Tauri keys the drag
          off the event target, so the buttons inside stay clickable. */}
      <div className="tb-slot" data-tauri-drag-region>
        {children}
      </div>

      <div className="tb-controls">
        <button
          className="tb-btn"
          onClick={() => win.minimize()}
          aria-label={t("Свернуть")}
          title={t("Свернуть")}
        >
          <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
            <rect x="0" y="4.5" width="10" height="1" fill="currentColor" />
          </svg>
        </button>
        <button
          className="tb-btn"
          onClick={() => win.toggleMaximize()}
          aria-label={maximized ? "Свернуть в окно" : "Развернуть"}
          title={maximized ? "Свернуть в окно" : "Развернуть"}
        >
          {maximized ? (
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <rect x="0" y="2.5" width="7" height="7" fill="none" stroke="currentColor" />
              <path d="M2.5 2.5V0.5H9.5V7.5H7.5" fill="none" stroke="currentColor" />
            </svg>
          ) : (
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <rect x="0.5" y="0.5" width="9" height="9" fill="none" stroke="currentColor" />
            </svg>
          )}
        </button>
        <button
          className="tb-btn tb-close"
          onClick={() => win.close()}
          aria-label={t("Закрыть")}
          title={t("Закрыть")}
        >
          <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
            <path d="M0 0L10 10M10 0L0 10" stroke="currentColor" fill="none" />
          </svg>
        </button>
      </div>
    </div>
  );
}
