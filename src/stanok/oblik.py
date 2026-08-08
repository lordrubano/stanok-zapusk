# -*- coding: utf-8 -*-
"""Облик экранов станка: вид пакета интерфейса 1.2 в одном месте.

Пакет 1.2 принят владельцем как единственный образец вида. До сегодня его
правила жили в сборщике показа (``tools/pokaz.py``), а тот отменён вместе со
всеми тремя редакциями показа. Экраны узла звали классы этого вида — плитки,
врезку, точки состояний, — а самих правил на узле не было: разметка была с
макета, вид не был.

Здесь правила лежат **в ядре**, а не в оснастке: экран без вида — это не
«почти готово», это другой экран. Числа, цвета и отступы взяты из пакета 1.2
без правки: ни одного своего оттенка тут нет.
"""

from __future__ import annotations

OBLIK_VERSION = "oblik/1"

# Правила ровно те, что нужны экранам узла. Что не показывается — того здесь
# нет: неиспользуемые правила не украшают, а лгут о составе.
СТИЛЬ = """
body { background: #f2f6fb; color: #16233a; }
.shapka { background: #14283f; color: #fff; padding: 16px 24px; margin: -24px
          -24px 22px; display: flex; justify-content: space-between;
          align-items: center; flex-wrap: wrap; gap: 12px; }
.shapka .imya { font-size: 20px; font-weight: 700; letter-spacing: .01em; }
.shapka .sprava { font-size: 14px; color: #b9c4d4; }
.taby { display: flex; gap: 10px; flex-wrap: wrap; }
.tab { background: #1e3552; color: #c8d4e4; border-radius: 8px;
       padding: 9px 16px; font-size: 12.5px; font-weight: 700;
       letter-spacing: .04em; text-transform: uppercase;
       text-decoration: none; }
.tab-tek { background: #2b5ce6; color: #fff; }
.ekran { display: block; }
.prochie { background: #1e3552; color: #b9c4d4; margin: -22px -24px 22px;
           padding: 8px 24px; font-size: 13px; }
.prochie a { color: #cfe0ff; text-decoration: none; }
.prochie a:hover { text-decoration: underline; }
a.plitka { text-decoration: none; color: inherit; display: block; }
.glavnoe a.chto { text-decoration: none; color: inherit; }
.dvekol { display: grid; grid-template-columns: minmax(0,1.85fr) minmax(0,1fr);
          gap: 20px; align-items: start; }
.ind { border-bottom: 1px solid #eef1f6; padding: 11px 0; }
.ind:last-child { border-bottom: 0; }
.ind .im { font-weight: 700; }
.ind .zn { color: #5b6b85; font-size: 14px; }
h1 { font-size: 26px; font-weight: 700; margin: 0 0 4px; }
p.pod { color: #5b6b85; margin: 0 0 22px; font-size: 16px; }
.plitki { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px;
          margin: 22px 0; }
.plitka { border-radius: 10px; padding: 14px 16px; border: 1px solid #0000000f; }
.plitka .p { font-size: 12px; font-weight: 700; letter-spacing: .06em;
             text-transform: uppercase; margin-bottom: 6px; }
.plitka .n { font-size: 28px; font-weight: 700; line-height: 1; }
.pl-seraya { background: #eef2f7; } .pl-seraya .p { color: #5b6b85; }
.pl-zheltaya { background: #fdf3d3; } .pl-zheltaya .p { color: #8a6b12; }
.pl-sinyaya { background: #e7eefc; } .pl-sinyaya .p { color: #2b5ce6; }
.pl-zelenaya { background: #e6f4ea; } .pl-zelenaya .p { color: #1e8e3e; }
.pl-krasnaya { background: #fdeaea; } .pl-krasnaya .p { color: #c5221f; }
.karta { background: #fff; border: 1px solid #dde3ec; border-radius: 12px;
         padding: 22px 24px; margin-bottom: 20px; }
.mnk { font-size: 12.5px; font-weight: 700; letter-spacing: .07em;
       text-transform: uppercase; color: #2b5ce6; margin-bottom: 14px; }
.vrezka { background: #fffbe8; border: 1px solid #e8b93a; border-radius: 9px;
          padding: 14px 16px; margin-bottom: 20px; }
.vrezka b { color: #8a6b12; display: block; margin-bottom: 4px; }
.vrezka span { color: #5b4a12; font-size: 14px; }
table.svoystva { border-collapse: collapse; margin-bottom: 22px; width: auto; }
table.svoystva th { text-align: left; font-weight: 700; color: #16233a;
                    padding: 6px 34px 6px 0; vertical-align: top;
                    white-space: nowrap; border: 0; }
table.svoystva td { padding: 6px 0; color: #33445e; border: 0; }
.knopki { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
.sinyaya { background: #2b5ce6; color: #fff; border-radius: 8px;
           padding: 14px 30px; font-weight: 700; font-size: 14.5px;
           letter-spacing: .04em; text-transform: uppercase; }
.pogashena { background: #e3e8ef; color: #8593a8; border-radius: 8px;
             padding: 14px 26px; font-weight: 700; text-align: center;
             text-transform: uppercase; letter-spacing: .04em; }
.tochka { display: inline-block; width: 9px; height: 9px; border-radius: 50%;
          margin-right: 9px; vertical-align: 1px; }
.t-zel { background: #1e8e3e; } .t-zhel { background: #d99a0b; }
.t-ser { background: #9aa4b2; } .t-kras { background: #c5221f; }
table.dok { border-collapse: collapse; width: 100%; font-size: 13.5px; }
table.dok th { text-align: left; font-weight: 700; padding: 8px 10px 8px 0;
               border-bottom: 1px solid #dde3ec; }
table.dok td { padding: 8px 10px 8px 0; border-bottom: 1px solid #eef1f6;
               color: #33445e; }
.snoska { color: #8a6b12; font-weight: 700; font-size: 13.5px;
          margin-top: 14px; }
.sopost { border: 1px solid #dde3ec; border-radius: 9px; padding: 13px 15px;
          margin-bottom: 12px; background: #fbfcfe; }
.sopost .sost { font-size: 13.5px; }
.sost-zel { color: #1e8e3e; } .sost-zhel { color: #8a6b12; font-weight: 700; }
.sost-kras { color: #c5221f; font-weight: 700; }
.tih { opacity: .75; font-size: 13px; color: #5b6b85; }
@media (max-width: 1080px) {
  .plitki { grid-template-columns: repeat(2, 1fr); }
  .dvekol { grid-template-columns: 1fr; }
}
"""

# Цвета очередей — с макета владельца, не по вкусу.
ЦВЕТ_ОЧЕРЕДИ = {
    "новые": "pl-seraya",
    "согласовать шаблон": "pl-zheltaya",
    "обрабатываются": "pl-sinyaya",
    "проверить": "pl-zheltaya",
    "готово": "pl-zelenaya",
    "заблокировано": "pl-krasnaya",
    "пуста": "pl-seraya",
}

ТОЧКА = {"принят": "t-zel", "отвергнут": "t-kras", "ждёт": "t-ser",
         "заменён": "t-zhel"}


def стилем(*куски: str) -> str:
    """Собирает правила в один вставной блок страницы."""
    return "<style>" + "".join(куски) + "</style>"


__all__ = ["OBLIK_VERSION", "СТИЛЬ", "ТОЧКА", "ЦВЕТ_ОЧЕРЕДИ", "стилем"]
