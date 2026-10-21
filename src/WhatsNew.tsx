import { useEffect, useRef } from "react";
import { Icon } from "./components";
import { useT } from "./i18n";
import { APP_VERSION, RELEASE_LINE, RELEASE_NAME } from "./version";

/**
 * What changed in this release, said once.
 *
 * Shown after an update — not on a first launch, where everything is new and
 * a changelog would only stand between the user and the scan — and reachable
 * again from the help screen and the command palette.
 */

const ITEMS: { icon: string; title: string; desc: string }[] = [
  {
    icon: "account_tree",
    title: "Движок читает настоящий код",
    desc: "Запрос на три строки и цепочка вызовов с точкой в начале строки больше не обрывают поток. Функции видны в Java, C#, Kotlin, Scala, Ruby, Elixir и Perl, а параметры обработчиков Spring, ASP.NET, NestJS, FastAPI и Flask — это источники ввода.",
  },
  {
    icon: "balance",
    title: "Честная оценка",
    desc: "Худшая находка задаёт пределы: мелочи не доводят до F, критическая уязвимость не даёт подняться выше C. Повторы одной причины весят всё меньше. «Почему такая оценка?» раскрывает всю арифметику.",
  },
  {
    icon: "trending_up",
    title: "План исправлений",
    desc: "Что поднимет оценку сильнее всего — по шагам, с баллами и классом после каждого. Каждое обещание проверено пересчётом.",
  },
  {
    icon: "stacks",
    title: "Повторы — одной строкой",
    desc: "«Свернуть повторы» оставляет строку на причину с меткой ×N; остальные места — в карточке находки.",
  },
  {
    icon: "difference",
    title: "Только изменения (BETA)",
    desc: "Проверка файлов, изменённых с последнего коммита, — правка до коммита за секунды.",
  },
  {
    icon: "palette",
    title: "Новый облик",
    desc: "Своя иконка приложения вместо стандартной, иконки Material Symbols Rounded — заполненные у активной вкладки и включённого переключателя, — и разделы дашборда с цветными метками.",
  },
  {
    icon: "shield_lock",
    title: "Безопасность",
    desc: "Папка с чужим .git больше не может запустить свою команду через git, который вызывает сканер.",
  },
];

/** True when the user has used an earlier version but not seen this note. */
export function shouldShowWhatsNew(): boolean {
  try {
    const seen = localStorage.getItem("vs.seenRelease");
    if (seen === RELEASE_LINE) return false;
    // Without the key, only someone who has used the app before gets the note.
    if (seen === null) {
      const returning = ["vs.recent", "vs.localPath", "vs.mode"].some((k) => localStorage.getItem(k) !== null);
      if (!returning) localStorage.setItem("vs.seenRelease", RELEASE_LINE);
      return returning;
    }
    return true;
  } catch {
    return false;
  }
}

export function markWhatsNewSeen(): void {
  try {
    localStorage.setItem("vs.seenRelease", RELEASE_LINE);
  } catch {
    /* storage refused: the note shows again next time, which is harmless */
  }
}

export function WhatsNew({ onClose }: { onClose: () => void }) {
  const t = useT();
  const okRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    okRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="palette-backdrop wn-backdrop" onClick={onClose}>
      <div
        className="wn"
        role="dialog"
        aria-modal="true"
        aria-labelledby="wn-title"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="wn-head">
          <div className="wn-mark">
            <Icon name="bolt" />
          </div>
          <div>
            <div className="wn-kicker">{t("Что нового")}</div>
            <h2 id="wn-title" className="wn-title">
              VulnScope {RELEASE_LINE} — {RELEASE_NAME}
            </h2>
          </div>
        </div>
        <ul className="wn-list">
          {ITEMS.map((it) => (
            <li key={it.title} className="wn-item">
              <Icon name={it.icon} />
              <div>
                <div className="wn-item-title">{t(it.title)}</div>
                <div className="wn-item-desc">{t(it.desc)}</div>
              </div>
            </li>
          ))}
        </ul>
        <div className="wn-foot">
          <span className="wn-version">{APP_VERSION}</span>
          <button ref={okRef} className="btn btn-primary" onClick={onClose}>
            {t("Понятно")}
          </button>
        </div>
      </div>
    </div>
  );
}
