import { Icon } from "./components";
import { useT } from "./i18n";

/**
 * The in-app reference. A scanner has a lot of moving parts — several engines,
 * a data-flow analysis, a security score, badges with specific meanings — and
 * "what does this actually do?" deserves an answer that is not the source code.
 * Everything the app can do is described here, grouped by what the user is
 * trying to understand.
 */

interface HelpItem {
  icon: string;
  term: string;
  desc: string;
}

interface HelpSection {
  icon: string;
  title: string;
  intro?: string;
  items: HelpItem[];
}

const SECTIONS: HelpSection[] = [
  {
    icon: "shield",
    title: "Что это",
    intro:
      "VulnScope — локальный сканер безопасности кода. Он ничего не отправляет наружу (кроме запросов к базе CVE, и то по желанию): весь анализ идёт на вашей машине. Укажите папку или ссылку на GitHub-репозиторий — и получите размеченный отчёт.",
    items: [],
  },
  {
    icon: "widgets",
    title: "Движки поиска",
    items: [
      { icon: "rule", term: "Встроенные правила", desc: "Больше 270 паттернов на 38 языках плюс детекторы секретов. Каждая находка размечена CWE, OWASP и уровнем важности." },
      { icon: "route", term: "Анализ потока данных", desc: "Флагман: прослеживает пользовательский ввод от источника до опасного вызова и показывает весь путь. Только подтверждённые находки, каждая самопроверяема." },
      { icon: "key", term: "Секреты в коде", desc: "Ключи, токены и пароли в исходниках. Значение секрета никогда не попадает в отчёт — только факт и место." },
      { icon: "inventory_2", term: "CVE в зависимостях", desc: "Манифесты сверяются с базой OSV.dev (с кэшем). Показывает уязвимые пакеты и версию, где исправлено." },
      { icon: "terminal", term: "Внешние сканеры", desc: "Semgrep, Bandit, Trivy, gitleaks и другие подключаются по желанию; их находки объединяются с встроенными без дублей." },
      { icon: "science", term: "Эвристики (BETA)", desc: "Подозрительные места, которые точные правила не поймали. Живут на отдельной вкладке и не влияют на счётчики и оценку." },
    ],
  },
  {
    icon: "verified_user",
    title: "Флагман: оценка и пути атаки",
    items: [
      { icon: "shield", term: "Оценка защищённости", desc: "Весь отчёт в одном балле 0–100 и классе A–F. Находки взвешены по важности и по реальной достижимости из недоверенного ввода." },
      { icon: "my_location", term: "Достижимость", desc: "Находка, до которой реально доходит пользовательский ввод, помечена «Достижимо» и весит в оценке больше — «присутствует» не то же, что «эксплуатируемо»." },
      { icon: "conversion_path", term: "Пути атаки", desc: "На дашборде — сами маршруты «точка входа → опасный вызов», отсортированные по опасности. Клик открывает находку." },
      { icon: "login", term: "Точка входа", desc: "Движок определяет, откуда входит ввод: HTTP-запрос, аргумент командной строки, переменная окружения или стандартный ввод." },
    ],
  },
  {
    icon: "account_tree",
    title: "Анализ потока данных подробно",
    items: [
      { icon: "linear_scale", term: "Межпроцедурный", desc: "Поток прослеживается через вызовы функций-хелперов, а не только внутри одной функции." },
      { icon: "alt_route", term: "Межфайловый", desc: "Источник в одном файле, приёмник в другом — цепочка честно переходит границу файла и открывается в нужном." },
      { icon: "cleaning_services", term: "Санитайзеры", desc: "Экранирование, параметризация и проверка по пути обрывают поток — в том числе пользовательские функции-санитайзеры." },
      { icon: "code", term: "Классы уязвимостей", desc: "Инъекция команд и SQL, path traversal, SSRF, выполнение кода, XSS и открытый редирект." },
    ],
  },
  {
    icon: "sell",
    title: "Значки находок",
    items: [
      { icon: "route", term: "ПОТОК", desc: "Находка с прослеженным путём данных от источника до приёмника." },
      { icon: "my_location", term: "Достижимо", desc: "Паттерн-находка лежит на прослеженном пути данных — по-настоящему достижима для атакующего." },
      { icon: "account_tree", term: "СВЯЗКА", desc: "Несколько подозрительных мест в одном файле, усиливающих друг друга в вероятную цепочку эксплуатации (BETA)." },
      { icon: "science", term: "BETA", desc: "Эвристическая, ещё не подтверждённая находка — для ручной проверки." },
      { icon: "fiber_new", term: "новое", desc: "Не было в предыдущем сканировании этой цели." },
    ],
  },
  {
    icon: "tune",
    title: "Работа с находками",
    items: [
      { icon: "filter_alt", term: "Фильтры", desc: "По важности, файлу, поиску и «только новые». Активные фильтры показаны строкой, каждый снимается одним кликом; счётчики следуют за фильтром." },
      { icon: "account_tree", term: "Дерево файлов", desc: "Слева — файлы с находками; выбор файла сужает список и счётчики к нему." },
      { icon: "edit", term: "Правка и перепроверка", desc: "Код можно поправить прямо в просмотрщике и перепроверить: исправленное гаснет, а файл загорается «Чисто»." },
      { icon: "visibility_off", term: "Подавление", desc: "Ложное срабатывание можно заглушить — оно уходит из счётчиков, а правило пишется в .vulnscope-ignore внутри проекта." },
    ],
  },
  {
    icon: "download",
    title: "Экспорт и отчётность",
    items: [
      { icon: "summarize", term: "Отчёт (PDF)", desc: "Экран отчёта для руководства: оценка, динамика с прошлого скана, график за последние сканы, эффективность, разбивки по категориям и сотрудникам. Печать в PDF одной кнопкой." },
      { icon: "data_object", term: "JSON", desc: "Полные данные отчёта для машинной обработки." },
      { icon: "security", term: "SARIF 2.1.0", desc: "Формат GitHub code scanning и CI-дашбордов; путь потока данных выгружается как codeFlows." },
      { icon: "description", term: "Markdown / CSV / HTML", desc: "Для тикета, чата, таблицы или готового к просмотру документа. Можно выгрузить только отфильтрованную выборку." },
      { icon: "table_view", term: "Excel (книга)", desc: "Многолистовая книга: сводка с оценкой и динамикой, таблица находок, разбивка по ответственным. Открывается в Excel и LibreOffice без плагинов." },
      { icon: "account_balance", term: "Обмен с 1С", desc: "Выгрузка отчёта в XML с русскими элементами для загрузки в 1С. Импорт из 1С — реестр проектов (заполняет цель скана) и реестр сотрудников: отчёт сгруппирует находки по ответственным." },
      { icon: "person", term: "Автор строки", desc: "В git-репозитории каждая находка атрибутируется через git blame: кто последним менял строку, каким коммитом и когда." },
    ],
  },
  {
    icon: "settings",
    title: "Настройка",
    items: [
      { icon: "edit_note", term: "Свои правила", desc: "Свой формат правил с редактором и проверкой на живом сниппете. Хранятся отдельно от встроенных." },
      { icon: "palette", term: "Темы", desc: "10 схем плюс тонкая настройка любого цвета-токена; все проверены на контраст и различимость при цветовой слепоте." },
      { icon: "keyboard", term: "Горячие клавиши", desc: "Переназначаемые сочетания и командная палитра (Ctrl+K) для всего." },
      { icon: "accessibility_new", term: "Доступность", desc: "Масштаб интерфейса, всегда видимый фокус, подписи уровней, крупные цели, уменьшение анимации." },
    ],
  },
];

export function HelpScreen({ onClose }: { onClose: () => void }) {
  const t = useT();
  return (
    <div className="rules-screen">
      <div className="rules-bar">
        <button className="btn btn-ghost" onClick={onClose}>
          <Icon name="arrow_back" />
          {t("Назад")}
        </button>
        <div className="rules-title">
          <Icon name="help" />
          {t("Справка")}
        </div>
      </div>

      <div className="rules-body help-body">
        {SECTIONS.map((sec) => (
          <section key={sec.title} className="help-section">
            <h2 className="help-h2">
              <Icon name={sec.icon} />
              {t(sec.title)}
            </h2>
            {sec.intro && <p className="help-intro">{t(sec.intro)}</p>}
            {sec.items.length > 0 && (
              <div className="help-grid">
                {sec.items.map((it) => (
                  <div key={it.term} className="help-item">
                    <Icon name={it.icon} className="help-item-icon" />
                    <div>
                      <div className="help-term">{t(it.term)}</div>
                      <div className="help-desc">{t(it.desc)}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        ))}
        <p className="help-foot">{t("VulnScope — локальный анализ, код не покидает вашу машину.")}</p>
      </div>
    </div>
  );
}
