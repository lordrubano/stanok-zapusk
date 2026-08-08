# -*- coding: utf-8 -*-
"""Изолированный запуск обработчиков и принуждение пределов.

Шаг 24 плана. Нормативная основа — чертёж v3.0, раздел 14.1: «обработка в
изолированном процессе или контейнере без лишних прав; отсутствие сетевого
доступа в локальном маршруте». Раздел 14.2 задаёт единственное исключение —
внешнюю передачу, и она к локальному маршруту отношения не имеет.

Здесь же снимается отложенное с шага 21. Пределы времени и памяти были
объявлены, но не принуждались, а объявленный предел защитой не является: он
описывает намерение, а не поведение. Теперь их держит операционная система.

Как устроено:

* обработчик работает в **отдельном процессе**, а не в общем. Своя память, своё
  падение, свой конец. Что бы с ним ни случилось, станок продолжает работать;
* процесс запускается в **чистом виде** — без переменных окружения родителя,
  без пользовательских каталогов пакетов, с явно переданными путями поиска;
* **память** ограничена заданием операционной системы. Не измерением постфактум,
  а отказом в выделении: перебравший процесс не сможет взять лишнего;
* **время** ограничено убийством по часам. Не просьбой завершиться, а убийством:
  зависший разбор не уговаривают;
* **сеть** запрещена внутри процесса до загрузки любой библиотеки разбора;
* **новые процессы** запрещены и изнутри, и заданием снаружи.

Отказ — состояние, а не падение: всё, что может случиться с обработчиком,
возвращается отчётом с причиной.

Платформа. Пределы держит операционная система, а средства у систем разные:
на Windows это задание (Job Object), на прочих — ресурсные пределы процесса.
Различие спрятано в двух местах ниже; всё остальное общее.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .intake import APPROVED_LIMITS, IntakeLimits


SANDBOX_REPORT_VERSION = "sandbox-report/1"

KNOWN_LIMITATIONS = (
    "Запрет сети ставится внутри процесса. Он держит код, пользующийся "
    "обычными средствами языка, и именно этим закрывает главную угрозу: "
    "недоверенные данные, заставляющие доверенную библиотеку полезть в сеть. "
    "Код, сознательно обходящий язык через системные вызовы, он не удержит — "
    "для этого нужна песочница уровня системы (AppContainer или контейнер), "
    "и это отдельное решение владельца.",
    "Предел памяти держится заданием операционной системы. На системах без "
    "заданий используются ресурсные пределы процесса; поведение при исчерпании "
    "там иное — процесс получает отказ в выделении памяти, а не гибнет сразу.",
    "Доступ к файловой системе не ограничен: обработчику нужен исходный файл, а "
    "разграничение путей относится к разделу 14.3, который не открыт.",
)

# Вступление дочернего процесса. Только латинские буквы, и это не прихоть:
# командная строка Windows не переносит кириллицу в кодировке системы, а
# переданная через ``-c`` строка проходит именно через неё. Всё осмысленное
# вынесено в stanok/_sandbox_child.py; здесь ровно столько, чтобы найти его.
#
# Ключи обмена латинские по той же причине: их читает это вступление.
# Вступление ещё и однострочное: перевод строки внутри довода командной строки
# Windows не переносит, и запуск обрывается на «Unable to create process».
_ВСТУПЛЕНИЕ = (
    "import json,sys;"
    "t=json.loads(sys.stdin.buffer.read().decode('utf-8'));"
    "sys.path[:0]=t['path'];"
    "import stanok._sandbox_child as c;"
    "c.main(t)"
)


@dataclass(frozen=True, slots=True)
class SandboxReport:
    """Чем кончился изолированный запуск."""

    schema_version: str
    исход: str
    код: str | None = None
    объяснение: str = ""
    значение: object = None
    измерения: dict = field(default_factory=dict)

    @property
    def получилось(self) -> bool:
        return self.исход == "готово"

    def as_json(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "исход": self.исход,
            "код": self.код,
            "объяснение": self.объяснение,
            "измерения": dict(sorted(self.измерения.items())),
        }


# --------------------------------------------------------------- Windows

def _клетка_windows(limits: IntakeLimits):
    """Задание операционной системы: предел памяти и предел числа процессов.

    Возвращает пару «применить к процессу, снять мерку», либо None, если
    заданий в этой системе нет.
    """

    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(имя, ctypes.c_ulonglong) for имя in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class BASIC_LIMIT(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED_LIMIT(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC_LIMIT),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    LIMIT_ACTIVE_PROCESS = 0x00000008
    LIMIT_PROCESS_MEMORY = 0x00000100
    LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
    LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    EXTENDED_INFO_CLASS = 9
    PROCESS_ALL_ACCESS = 0x1F0FFF

    задание = kernel.CreateJobObjectW(None, None)
    if not задание:
        return None

    сведения = EXTENDED_LIMIT()
    сведения.BasicLimitInformation.LimitFlags = (
        LIMIT_PROCESS_MEMORY | LIMIT_ACTIVE_PROCESS
        | LIMIT_KILL_ON_JOB_CLOSE | LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
    сведения.BasicLimitInformation.ActiveProcessLimit = 1
    сведения.ProcessMemoryLimit = limits.max_memory_bytes
    if not kernel.SetInformationJobObject(
            задание, EXTENDED_INFO_CLASS, ctypes.byref(сведения),
            ctypes.sizeof(сведения)):
        kernel.CloseHandle(задание)
        return None

    def применить(pid):
        дескриптор = kernel.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not дескриптор:
            return False
        принято = kernel.AssignProcessToJobObject(задание, дескриптор)
        kernel.CloseHandle(дескриптор)
        return bool(принято)

    def снять_мерку():
        снимок = EXTENDED_LIMIT()
        нужно = wintypes.DWORD(0)
        if kernel.QueryInformationJobObject(
                задание, EXTENDED_INFO_CLASS, ctypes.byref(снимок),
                ctypes.sizeof(снимок), ctypes.byref(нужно)):
            пик = снимок.PeakProcessMemoryUsed
        else:
            пик = 0
        kernel.CloseHandle(задание)
        return пик

    return применить, снять_мерку


# ----------------------------------------------------------------- прочие

def _клетка_posix(limits: IntakeLimits):
    """Ресурсные пределы процесса там, где заданий нет."""

    import resource

    def подготовить():
        resource.setrlimit(
            resource.RLIMIT_AS,
            (limits.max_memory_bytes, limits.max_memory_bytes))
        resource.setrlimit(
            resource.RLIMIT_CPU,
            (limits.max_duration_seconds, limits.max_duration_seconds))

    return подготовить


# ------------------------------------------------------------------ запуск


# Что достаётся обработчику из окружения родителя. Список закрытый: всё, чего
# в нём нет, до обработчика не доходит — ни ключи, ни доступы, ни пути к чужим
# каталогам. Оставлено ровно то, без чего не запускается сам язык.
СРЕДА_РАЗРЕШЕНО = (
    "SystemRoot", "SystemDrive", "windir", "COMSPEC", "PATHEXT",
    "TEMP", "TMP", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
)


def _чистая_среда():
    """Окружение обработчика: только необходимое, ничего лишнего.

    Пустая среда выглядит строже, но на Windows с ней не запускается сам
    истолкователь, и строгость оборачивается неработающей защитой. Поэтому
    список закрытый, а не пустой, и в нём нет ни одной переменной, способной
    что-нибудь выдать.
    """
    среда = {}
    for имя in СРЕДА_РАЗРЕШЕНО:
        for ключ, значение in os.environ.items():
            if ключ.lower() == имя.lower() and значение:
                среда[ключ] = значение
    # Полный PATH родителя обработчику не достаётся: там пути к чужим
    # средствам и к тому, что запускать ему незачем. Но и пустым его оставить
    # нельзя — с пустым PATH истолкователь на Windows не запускается вовсе, и
    # защита обернулась бы неработающим запуском. Оставляем один системный
    # каталог: без него не создаётся процесс, а лишнего в нём нет.
    # Имена переменных берём как есть, а ищем без учёта регистра: Windows
    # хранит их как придётся, и точное совпадение однажды уже дало пустой путь.
    по_имени = {ключ.lower(): значение for ключ, значение in среда.items()}
    корень_системы = по_имени.get("systemroot") or по_имени.get("windir") or ""
    среда["PATH"] = str(Path(корень_системы) / "System32") if корень_системы else ""

    # Windows требует, чтобы блок окружения был упорядочен по именам. Питон
    # передаёт его в том порядке, в каком лежит в словаре, и неупорядоченный
    # блок оборачивается отказом «Unable to create process» — без единого
    # намёка на настоящую причину.
    return {ключ: среда[ключ] for ключ in sorted(среда, key=str.upper)}


def _истолкователь() -> str:
    """Настоящий истолкователь, а не переходник виртуального окружения.

    ``python.exe`` из виртуального окружения — переходник: он не работает сам,
    а **запускает** настоящий истолкователь. В задании, разрешающем один
    процесс, он упирается в этот запрет и умирает с невнятным «Unable to create
    process», не сказав о настоящей причине ни слова.

    Поднимать предел числа процессов ради переходника значило бы ослабить
    защиту из-за особенности запуска. Берём настоящий истолкователь, а нужные
    ему каталоги пакетов передаём явно.
    """
    основной = getattr(sys, "_base_executable", None)
    if основной and Path(основной).is_file():
        return основной
    return sys.executable


def _каталоги_пакетов() -> list[str]:
    """Каталоги установленных пакетов текущего окружения.

    Истолкователь запускается в отгороженном виде и своего окружения не видит,
    поэтому пути к пакетам передаются явно. Передаётся только то, что уже есть
    в путях родителя: ничего нового обработчику не открывается.
    """
    return [место for место in sys.path
            if место.endswith("site-packages") and Path(место).is_dir()]


def запустить(
    модуль: str,
    функция: str,
    довод=None,
    *,
    limits: IntakeLimits = APPROVED_LIMITS,
    путь=None,
) -> SandboxReport:
    """Выполняет обработчик в изолированном процессе под пределами.

    Ничего не бросает: любой исход — отчёт с причиной.
    """

    корень = str(Path(__file__).resolve().parents[1])
    задача = {
        "module": модуль,
        "function": функция,
        "argument": довод,
        "path": (list(путь) if путь else [корень]) + _каталоги_пакетов(),
    }

    среда = _чистая_среда()

    клетка = None
    подготовить = None
    if sys.platform == "win32":
        try:
            клетка = _клетка_windows(limits)
        except (OSError, AttributeError):
            клетка = None
    else:
        try:
            подготовить = _клетка_posix(limits)
        except ImportError:
            подготовить = None

    начало = time.monotonic()
    try:
        дитя = subprocess.Popen(
            [_истолкователь(), "-I", "-c", _ВСТУПЛЕНИЕ],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=среда,
            preexec_fn=подготовить if подготовить else None,
        )
    except OSError as беда:
        return SandboxReport(
            SANDBOX_REPORT_VERSION, "отказ", "E_SANDBOX_START",
            f"обработчик не запустился: {беда}")

    применить, снять_мерку = клетка if клетка else (None, None)
    в_клетке = применить(дитя.pid) if применить else False

    убит_по_времени = False
    try:
        вывод, ошибки = дитя.communicate(
            json.dumps(задача, ensure_ascii=False).encode("utf-8"),
            timeout=limits.max_duration_seconds)
    except subprocess.TimeoutExpired:
        # Зависший разбор не уговаривают: убиваем и считаем это отказом.
        убит_по_времени = True
        дитя.kill()
        вывод, ошибки = дитя.communicate()
    прошло = time.monotonic() - начало
    пик = снять_мерку() if снять_мерку else 0

    измерения = {"duration_seconds": int(прошло), "memory_bytes": int(пик),
                 "в_клетке": 1 if в_клетке else 0}

    if убит_по_времени:
        return SandboxReport(
            SANDBOX_REPORT_VERSION, "отказ", "E_LIMIT_DURATION",
            f"обработчик убит: работа дольше предела "
            f"{limits.max_duration_seconds} с",
            None, измерения)

    текст = (вывод or b"").decode("utf-8", errors="replace").strip()
    жалобы = (ошибки or b"").decode("utf-8", errors="replace").strip()
    if not текст:
        # Молчание при ненулевом коде и без единой жалобы — это смерть от
        # предела памяти: задание не даёт процессу взять лишнего, и он гибнет,
        # не успев ничего сказать. Если же жалоба есть, значит беда другая, и
        # выдавать её за предел памяти нельзя — такая подмена уже случалась.
        умер_молча = дитя.returncode not in (0, None) and not жалобы
        причина = "E_LIMIT_MEMORY" if умер_молча else "E_SANDBOX_NO_ANSWER"
        return SandboxReport(
            SANDBOX_REPORT_VERSION, "отказ", причина,
            жалобы or f"обработчик не ответил, код выхода {дитя.returncode}",
            None, измерения)

    try:
        ответ = json.loads(текст)
    except ValueError:
        return SandboxReport(
            SANDBOX_REPORT_VERSION, "отказ", "E_SANDBOX_BAD_ANSWER",
            "ответ обработчика не разобран", None, измерения)

    if ответ.get("исход") == "готово":
        return SandboxReport(
            SANDBOX_REPORT_VERSION, "готово", None, "",
            ответ.get("значение"), измерения)

    код = ответ.get("код") or _код_по_породе(ответ.get("порода", ""))
    return SandboxReport(
        SANDBOX_REPORT_VERSION, "отказ", код,
        ответ.get("объяснение", ""), None, измерения)


def _код_по_породе(порода: str) -> str:
    """Причина отказа по породе исключения обработчика."""

    return {
        "СетьЗапрещена": "E_SANDBOX_NETWORK",
        "PermissionError": "E_SANDBOX_NO_RIGHTS",
        "MemoryError": "E_LIMIT_MEMORY",
    }.get(порода, "E_HANDLER_FAILED")


__all__ = [
    "KNOWN_LIMITATIONS",
    "SANDBOX_REPORT_VERSION",
    "SandboxReport",
    "запустить",
]
