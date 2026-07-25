import { Fragment, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon } from "./components";
import { useT } from "./i18n";
import { InstallResult, ToolId, ToolsInfo, ToolStatus } from "./types";

/**
 * The external-scanner catalogue.
 *
 * Installing goes through the user's own package manager (pip/cargo/scoop/…),
 * never by fetching a binary ourselves: those managers verify what they fetch,
 * and a scanner that downloads and runs arbitrary executables would be the
 * supply-chain weakness it exists to report. The exact command is always shown
 * before it runs.
 */
export function ToolsCard({
  tools,
  setTools,
  enabledTools,
  setEnabledTools,
}: {
  tools: ToolsInfo;
  setTools: (t: ToolsInfo) => void;
  enabledTools: Set<ToolId>;
  setEnabledTools: (v: Set<ToolId>) => void;
}) {
  const tr = useT();
  const [expanded, setExpanded] = useState<ToolId | null>(null);
  const [busy, setBusy] = useState<ToolId | null>(null);
  const [result, setResult] = useState<Record<string, InstallResult>>({});
  const [rechecking, setRechecking] = useState(false);
  const [showAll, setShowAll] = useState(false);

  /**
   * Installed scanners first, catalogue order preserved inside each group.
   *
   * The list mixed "ready to switch on" with "would need installing", so the
   * actionable half was scattered through the other. A stable sort by
   * availability puts everything you can actually use at the top and turns the
   * rest into a clearly separate "could add" tail.
   */
  const integrated = useMemo(
    () =>
      tools.tools
        .filter((t) => t.integrated)
        .map((t, i) => ({ t, i }))
        .sort((a, b) => Number(b.t.available) - Number(a.t.available) || a.i - b.i)
        .map(({ t }) => t),
    [tools]
  );
  const extra = useMemo(() => tools.tools.filter((t) => !t.integrated), [tools]);
  const ready = integrated.filter((t) => t.available).length;

  const recheck = async () => {
    setRechecking(true);
    try {
      // force: the answer is cached per session, and this button exists
      // precisely for when it has gone stale.
      setTools(await invoke<ToolsInfo>("get_tools", { force: true }));
    } finally {
      setRechecking(false);
    }
  };

  const install = async (t: ToolStatus, manager: string) => {
    setBusy(t.tool);
    try {
      const r = await invoke<InstallResult>("install_tool", { tool: t.tool, manager });
      setResult((prev) => ({ ...prev, [t.tool]: r }));
      if (r.ok) await recheck();
    } catch (e) {
      setResult((prev) => ({
        ...prev,
        [t.tool]: { ok: false, command: "", output: String(e) },
      }));
    } finally {
      setBusy(null);
    }
  };

  const copy = (cmd: string) => navigator.clipboard.writeText(cmd).catch(() => {});


  /** Groups the backend's scope string into a colour family for the avatar, so
   *  ten near-identical rows can be told apart at a glance. */
  const scopeKind = (scope: string): string => {
    if (scope === tr("Секреты")) return "secrets";
    if (scope === tr("Зависимости")) return "deps";
    if (scope === tr("Инфраструктура")) return "infra";
    if (scope === tr("Много языков")) return "multi";
    return "lang";
  };

  const row = (t: ToolStatus) => {
    const on = enabledTools.has(t.tool);
    const open = expanded === t.tool;
    const res = result[t.tool];
    const routes = t.installOptions.filter((o) => o.available);

    return (
      <div key={t.tool} className={`tool-row ${t.available ? "" : "missing"}`}>
        <div className="tool-main">
          {t.integrated ? (
            <label
              className={`tool-check ${on ? "checked" : ""} ${!t.available ? "disabled" : ""}`}
              title={t.available ? tr("Использовать при сканировании") : tr("Сначала установите")}
            >
              <input
                type="checkbox"
                disabled={!t.available}
                checked={on}
                onChange={(e) => {
                  const next = new Set(enabledTools);
                  if (e.target.checked) next.add(t.tool);
                  else next.delete(t.tool);
                  setEnabledTools(next);
                }}
              />
              <span className="opt-box">
                <Icon name="check" />
              </span>
            </label>
          ) : (
            <span
              className="tool-check disabled"
              title={tr("Пока не подключён к сканированию")}
              style={{ width: 16 }}
            />
          )}

          <span className={`tool-ava ${scopeKind(t.scope)}`} aria-hidden="true">
            {t.label.slice(0, 1).toUpperCase()}
          </span>

          <div className="tool-info">
            <div className="tool-name">
              {t.label}
              <span className="tag">{tr(t.scope)}</span>
              {t.available ? (
                <span className="tool-badge">{(t.version ?? "").slice(0, 32)}</span>
              ) : (
                <span className="tool-badge missing">{tr("не установлен")}</span>
              )}
              {!t.integrated && (
                <span className="tag" title={tr("Установить можно, но его вывод пока не разбирается")}>
                  {tr("не подключён")}
                </span>
              )}
            </div>
            <div className="tool-adds">{tr(t.adds)}</div>
          </div>

          {!t.available && t.installOptions.length > 0 && (
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setExpanded(open ? null : t.tool)}
              disabled={busy === t.tool}
            >
              <Icon
                name={busy === t.tool ? "progress_activity" : open ? "expand_less" : "download"}
                className={busy === t.tool ? "spin" : ""}
              />
              {busy === t.tool ? tr("Ставится…") : tr("Установить")}
            </button>
          )}
        </div>

        {open && !t.available && (
          <div className="tool-install">
            {routes.length === 0 ? (
              <div className="tools-note" style={{ marginBottom: 0 }}>
                <Icon name="info" />
                {tr("Ни один из подходящих пакетных менеджеров не найден. Установите вручную:")}{" "}
                <code>{t.installHint}</code>
              </div>
            ) : (
              <>
                <div className="tool-after" style={{ marginTop: 0, marginBottom: 8 }}>
                  {tr("Команда выполнится как есть, без шелла. Проверить её можно прямо здесь.")}
                </div>
                {routes.map((o) => (
                  <div key={o.manager} className="cmd-row">
                    <code>{o.command}</code>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => copy(o.command)}
                      title={tr("Скопировать")}
                    >
                      <Icon name="content_copy" />
                    </button>
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => install(t, o.manager)}
                      disabled={busy !== null}
                    >
                      <Icon name="play_arrow" />
                      {tr("Выполнить")}
                    </button>
                  </div>
                ))}
              </>
            )}

            {res && (
              <div className={`install-out ${res.ok ? "ok" : "fail"}`}>
                <div className="io-head">
                  <Icon name={res.ok ? "check_circle" : "error"} />
                  {res.ok ? tr("Установлено") : tr("Не удалось")}
                  <code>{res.command}</code>
                </div>
                <pre>{res.output}</pre>
              </div>
            )}

            <div
              className="ref-link"
              onClick={() => invoke("plugin:opener|open_url", { url: t.docsUrl }).catch(() => {})}
            >
              <Icon name="open_in_new" />
              {tr("Официальная страница проекта")}
            </div>
          </div>
        )}
      </div>
    );
  };

  const usable = integrated.filter((t) => t.available);
  const on = usable.filter((t) => enabledTools.has(t.tool)).length;
  const allOn = usable.length > 0 && on === usable.length;

  const toggleAll = () => {
    const next = new Set(enabledTools);
    if (allOn) usable.forEach((t) => next.delete(t.tool));
    else usable.forEach((t) => next.add(t.tool));
    setEnabledTools(next);
  };

  return (
    <div className="card">
      <div className="card-title">
        <Icon name="extension" />
        {tr("Внешние сканеры")}
        <div style={{ flex: 1 }} />
        {usable.length > 0 && (
          <button className="btn btn-ghost btn-sm" onClick={toggleAll}>
            <Icon name={allOn ? "remove_done" : "done_all"} />
            {allOn ? tr("Выключить все") : tr("Включить все")}
          </button>
        )}
        <button className="btn btn-ghost btn-sm" onClick={recheck} disabled={rechecking}>
          <Icon name="refresh" className={rechecking ? "spin" : ""} />
          {tr("Проверить снова")}
        </button>
      </div>

      {/* One segment per scanner. The count that matters is how many are *on*:
          installed-but-unchecked contributes nothing to a scan, and the old
          "9 из 10" happily read as full coverage while every box was empty. */}
      <div className="cov">
        <div className="cov-bar" title={tr("{on} включено, {installed} установлено, {missing} не установлено", { on, installed: ready - on, missing: integrated.length - ready })}>
          {integrated.map((t) => (
            <span
              key={t.tool}
              className={`cov-seg ${
                enabledTools.has(t.tool) ? "on" : t.available ? "idle" : "off"
              }`}
            />
          ))}
        </div>
        <div className="cov-legend">
          {tr("{n} из {total} сканеров участвуют в сканировании", { n: on, total: integrated.length })}
          {ready > on && <span className="cov-hint"> · {tr("{n} установлено, но выключено", { n: ready - on })}</span>}
        </div>
      </div>

      {ready < integrated.length && (
        <div className="tools-note">
          <Icon name="info" />
          {tr("Приложение работает и без них — это покрытие поверх {n} встроенных правил. Установка идёт через ваш пакетный менеджер, который сам проверяет подлинность пакета: скачивать бинарники напрямую сканер безопасности не должен.", { n: 115 })}
        </div>
      )}

      {/* A caption before the first not-installed row: the sort already groups
          them, this says what the boundary means. */}
      <div className="tool-list">
        {integrated.map((t, i) => (
          <Fragment key={t.tool}>
            {!t.available && integrated[i - 1]?.available && (
              <div className="tool-divider">{tr("Можно добавить")}</div>
            )}
            {row(t)}
          </Fragment>
        ))}
      </div>

      {extra.length > 0 && (
        <>
          <button className="show-more" onClick={() => setShowAll(!showAll)}>
            <Icon name={showAll ? "expand_less" : "expand_more"} />
            {showAll ? tr("Скрыть") : `Ещё ${extra.length} сканера`}
            <span className="tag">{tr("установка есть, разбор вывода — нет")}</span>
          </button>
          {showAll && <div className="tool-list">{extra.map(row)}</div>}
        </>
      )}
    </div>
  );
}

/**
 * Shown while the scanners are being probed.
 *
 * Probing means running `--version` for a dozen tools; semgrep alone takes two
 * seconds to start. Without this the card simply appeared out of nowhere a few
 * seconds in — and the reason it took that long was invisible, so it read as
 * the app being slow rather than as work in progress.
 */
export function ToolsLoading() {
  const tr = useT();
  return (
    <div className="card" aria-busy="true">
      <div className="card-title">
        <Icon name="extension" />
        {tr("Внешние сканеры")}
        <div style={{ flex: 1 }} />
        <span className="tool-badge">{tr("проверяем…")}</span>
      </div>

      <div className="cov">
        <div className="cov-bar cov-loading" role="presentation">
          {Array.from({ length: 10 }).map((_, i) => (
            <span key={i} className="cov-seg pending" style={{ animationDelay: `${i * 90}ms` }} />
          ))}
        </div>
        <div className="cov-legend" role="status">
          {tr("Спрашиваем у каждого сканера его версию — это запуск процесса на каждый, пара секунд.")}
        </div>
      </div>

      <div className="tool-list">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="tool-row sk-tool" style={{ animationDelay: `${i * 80}ms` }}>
            <span className="sk-bar" style={{ width: 16, height: 16, borderRadius: 4 }} />
            <span className="sk-bar" style={{ width: 26, height: 26, borderRadius: 8 }} />
            <span className="sk-lines">
              <span className="sk-bar" style={{ width: `${38 + i * 9}%` }} />
              <span className="sk-bar sk-sub" style={{ width: `${58 - i * 6}%` }} />
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
