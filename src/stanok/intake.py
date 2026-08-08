"""Приём файла как недоверенного входа и пределы обработки.

Шаги 20 и 21 плана. Нормативная основа — чертёж v3.0, раздел 14.1
«Недоверенный вход» и раздел 5.2, пункты 1–2 последовательности обработки:
принять файл как недоверенный вход, вычислить хеш исходных байтов, затем
проверить лимиты.

Два непереговорных принципа чертежа определяют здесь всё:

* **источник неизменяем** — модуль только читает; исходные байты не
  переписываются, не нормализуются и не чинятся;
* **неизвестное не равно правильному** — величина, которую никто не измерил,
  не считается уложившейся в предел. Непроверенный предел виден в паспорте
  как непроверенный, а не как пройденный.

Что модуль делает сам:

* считает ``document_id = sha256(исходные_байты)`` (раздел 6.2);
* стережёт предел размера **во время чтения**, а не после: файл больше предела
  не будет прочитан целиком ни при каких обстоятельствах;
* отвергает всё, что не является обычным файлом: ссылки, каталоги, устройства,
  именованные каналы;
* обезвреживает имя файла — наружу и в журналы идёт безопасное имя, а исходное
  сохраняется отдельно как данные, а не как путь;
* составляет паспорт входа ``intake-passport/2``.

Два входа в модуль различаются нарочно. ``accept_file`` бросает исключение,
когда вход вовсе не является файлом: это ошибка вызывающего, и в строгом
применении она обязана быть громкой. ``принять`` не бросает ничего — на общей
дороге обработки недоступный файл есть обычный исход, и у него должен быть
паспорт наравне с прочими.

Чего модуль не делает и не притворяется, что делает, — см. ``KNOWN_LIMITATIONS``.
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_module
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


INTAKE_SCHEMA_VERSION = "intake-passport/2"
"""Версия схемы паспорта.

Версия 2 добавила ``признаки`` и ``расшифровка`` — наблюдения политики шага 23.
Версия 1 наружу не выходила и в чужих руках не бывала, но менять схему без
смены номера нельзя даже в этом случае: привычка молча править схему однажды
обойдётся дорого.
"""

KNOWN_LIMITATIONS = (
    "Число страниц, глубину вложенности и распакованный объём измеряет тот, "
    "кто разбирает контейнер. Здесь эти величины только проверяются по "
    "пределам; сам разбор архивов и защита от бомб — шаг 22.",
    "Антивирусной проверки нет: политика и средство не утверждены владельцем. "
    "Отсутствие названо явно, чтобы не выдавалось за выполненное.",
)
"""Известные ограничения приёма.

Список существует затем, чтобы несделанное было видно. Пустой список означал бы,
что раздел 14.1 закрыт целиком, а он закрыт не весь.

Снято 04.08.2026 шагом 24: пределы времени и памяти были объявлены, но не
принуждались, и изоляции процесса не было. Теперь пределы держит операционная
система, обработчик работает в отдельном процессе без сети и без лишних прав —
см. ``stanok.sandbox``. Объявленный, но не принуждаемый предел защитой не
является, и держать такую запись в списке дольше было нельзя.
"""


class IntakeError(ValueError):
    """Ошибка приёма: файл недоступен или не является обычным файлом."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class Refusal:
    """Причина отказа во входе: машинный код и объяснение словами."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class IntakeLimits:
    """Утверждённые владельцем пределы недоверенного входа.

    Решение владельца от 03.08.2026, набор «рабочий». Чертёж v3.0 перечисляет
    виды пределов в разделе 14.1, но чисел не даёт; числа утверждены отдельно.
    Значения не меняются исполнителем без нового решения владельца.
    """

    # Все значения ниже утверждены владельцем.
    max_file_bytes: int = 104_857_600        # 100 МБ
    max_pages: int = 1_000
    max_duration_seconds: int = 300          # 5 минут
    max_memory_bytes: int = 1_073_741_824    # 1024 МБ
    max_container_depth: int = 5
    max_unpacked_bytes: int = 524_288_000    # 500 МБ
    max_compression_ratio: int = 100

    def __post_init__(self) -> None:
        for name in (
            "max_file_bytes",
            "max_pages",
            "max_duration_seconds",
            "max_memory_bytes",
            "max_container_depth",
            "max_unpacked_bytes",
            "max_compression_ratio",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise IntakeError(
                    "E_INVALID_LIMIT",
                    f"предел {name} должен быть целым числом больше нуля",
                )

    def as_json(self) -> dict[str, int]:
        """Пределы в виде, пригодном для паспорта и манифеста."""

        return {
            "max_file_bytes": self.max_file_bytes,
            "max_pages": self.max_pages,
            "max_duration_seconds": self.max_duration_seconds,
            "max_memory_bytes": self.max_memory_bytes,
            "max_container_depth": self.max_container_depth,
            "max_unpacked_bytes": self.max_unpacked_bytes,
            "max_compression_ratio": self.max_compression_ratio,
        }


APPROVED_LIMITS = IntakeLimits()
"""Утверждённый набор пределов. Общая точка правды для всего станка."""


# ----------------------------------------------------------------- имя файла

_RESERVED_WINDOWS_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{digit}" for digit in "123456789"}
    | {f"LPT{digit}" for digit in "123456789"}
)

_SAFE_FALLBACK = "bezymyannyj"
_MAX_SAFE_NAME = 120


def safe_name(raw: Any) -> str:
    """Обезвреженное имя файла: годится как имя, но не как путь.

    Недоверенное имя — такой же вход, как содержимое. Из него убирается всё,
    чем можно уйти за пределы каталога или подменить смысл: разделители путей,
    двоеточие тома, точки перехода в родительский каталог, управляющие символы,
    односторонние переопределения направления письма. Результат никогда не
    пуст и никогда не совпадает с зарезервированным именем Windows.
    """

    text = raw if isinstance(raw, str) else str(raw)
    # Символы переопределения направления письма скрывают настоящее расширение:
    # «счёт<RLO>fdp.exe» показывается как «счётexe.pdf».
    text = "".join(
        symbol for symbol in text
        if unicodedata.category(symbol) not in ("Cc", "Cf", "Cs", "Co", "Cn")
    )
    text = unicodedata.normalize("NFC", text)
    # Берём только последний элемент пути в обоих начертаниях: и «a/b», и «a\b»,
    # и «C:name» дадут одно имя без каталогов.
    text = PureWindowsPath(PurePosixPath(text).name).name
    for symbol in '<>:"/\\|?*':
        text = text.replace(symbol, "_")
    text = text.strip(" .")
    if len(text) > _MAX_SAFE_NAME:
        stem, dot, suffix = text.rpartition(".")
        if dot and 0 < len(suffix) <= 16:
            keep = max(1, _MAX_SAFE_NAME - len(suffix) - 1)
            text = f"{stem[:keep]}.{suffix}"
        else:
            text = text[:_MAX_SAFE_NAME]
        text = text.strip(" .")
    if not text or set(text) <= {"_"}:
        return _SAFE_FALLBACK
    stem = text.partition(".")[0].upper()
    if stem in _RESERVED_WINDOWS_NAMES:
        return f"{_SAFE_FALLBACK}_{text}"
    return text


# ------------------------------------------------------------------- паспорт


@dataclass(frozen=True, slots=True)
class IntakePassport:
    """Паспорт входа: что приняли, чем измерили и чем это кончилось.

    Паспорт составляется и для принятого файла, и для отвергнутого. Отказ —
    такой же результат приёма, как допуск, и он обязан быть предъявляемым.
    """

    schema_version: str
    document_id: str | None
    byte_size: int | None
    source_name: str
    stored_name: str
    suffix: str
    trust: str
    limits: Mapping[str, int]
    measurements: Mapping[str, int]
    refusals: tuple[Refusal, ...] = ()
    unchecked: tuple[str, ...] = ()
    признаки: tuple[str, ...] = ()
    расшифровка: str = "не требовалась"

    @property
    def accepted(self) -> bool:
        """Допущен ли файл к дальнейшей обработке."""

        return not self.refusals

    def as_json(self) -> dict[str, Any]:
        """Паспорт в виде канонизируемого JSON-объекта.

        Все величины целочисленные или строковые: float в каноническом контуре
        станка запрещён.
        """

        return {
            "schema_version": self.schema_version,
            "document_id": self.document_id,
            "byte_size": self.byte_size,
            "source_name": self.source_name,
            "stored_name": self.stored_name,
            "suffix": self.suffix,
            "trust": self.trust,
            "limits": dict(sorted(self.limits.items())),
            "measurements": dict(sorted(self.measurements.items())),
            "verdict": "accepted" if self.accepted else "rejected",
            "refusals": [
                {"code": refusal.code, "message": refusal.message}
                for refusal in self.refusals
            ],
            "unchecked": list(self.unchecked),
            "признаки": list(self.признаки),
            "расшифровка": self.расшифровка,
        }


# ------------------------------------------------------------------ шаг 20


_UNCHECKED_ALL = (
    "pages",
    "container_depth",
    "unpacked_bytes",
    "compression_ratio",
    "duration_seconds",
    "memory_bytes",
)
"""Величины, которые сам приём измерить не может.

Пока их никто не измерил, они числятся непроверенными. Это прямое следствие
принципа «неизвестное не равно правильному»: страница, которую не посчитали,
не считается уложившейся в предел.
"""

_CHUNK = 1 << 20


def _reject_special_file(path: Path) -> None:
    """Отвергает всё, что не является обычным файлом.

    Проверка идёт по ``lstat``: ``stat`` пошёл бы по ссылке и рассказал бы о
    цели, а не о том, что нам подсунули.
    """

    try:
        status = path.lstat()
    except OSError as exc:
        raise IntakeError(
            "E_INTAKE_UNREADABLE", f"файл недоступен: {path.name}"
        ) from exc

    mode = status.st_mode
    if stat_module.S_ISLNK(mode):
        raise IntakeError("E_INTAKE_NOT_REGULAR", "вход является ссылкой, а не файлом")
    if stat_module.S_ISDIR(mode):
        raise IntakeError("E_INTAKE_NOT_REGULAR", "вход является каталогом")
    if not stat_module.S_ISREG(mode):
        raise IntakeError(
            "E_INTAKE_NOT_REGULAR",
            "вход не является обычным файлом: устройство, канал или сокет",
        )


def accept_file(
    path: str | os.PathLike[str],
    *,
    limits: IntakeLimits = APPROVED_LIMITS,
    source_name: str | None = None,
) -> IntakePassport:
    """Принимает файл как недоверенный вход и составляет паспорт.

    Хеш считается потоково, кусками, и чтение прекращается, как только
    прочитанное превысило предел размера: слишком большой файл не попадает в
    память целиком даже на мгновение. Это не оптимизация, а часть защиты —
    иначе предел размера защищал бы только после того, как вред уже нанесён.

    Отказ по размеру означает, что ``document_id`` неизвестен: считать хеш
    дальше значило бы делать ровно то, что предел запрещает. Неизвестное поле
    остаётся пустым и не подменяется частичным хешем.
    """

    file_path = Path(path)
    _reject_special_file(file_path)

    declared = source_name if source_name is not None else file_path.name
    stored = safe_name(declared)
    suffix = PureWindowsPath(stored).suffix.lower()

    digest = hashlib.sha256()
    read_bytes = 0
    too_large = False
    try:
        with open(file_path, "rb") as handle:
            while True:
                chunk = handle.read(_CHUNK)
                if not chunk:
                    break
                read_bytes += len(chunk)
                if read_bytes > limits.max_file_bytes:
                    too_large = True
                    break
                digest.update(chunk)
    except OSError as exc:
        raise IntakeError(
            "E_INTAKE_UNREADABLE", f"файл не читается: {stored}"
        ) from exc

    if too_large:
        return IntakePassport(
            schema_version=INTAKE_SCHEMA_VERSION,
            document_id=None,
            byte_size=None,
            source_name=declared,
            stored_name=stored,
            suffix=suffix,
            trust="untrusted",
            limits=limits.as_json(),
            measurements={},
            refusals=(
                Refusal(
                    "E_LIMIT_FILE_BYTES",
                    f"размер файла превышает предел {limits.max_file_bytes} байт; "
                    "чтение прекращено, хеш исходных байтов не вычислялся",
                ),
            ),
            unchecked=_UNCHECKED_ALL,
        )

    return IntakePassport(
        schema_version=INTAKE_SCHEMA_VERSION,
        document_id=digest.hexdigest(),
        byte_size=read_bytes,
        source_name=declared,
        stored_name=stored,
        suffix=suffix,
        trust="untrusted",
        limits=limits.as_json(),
        measurements={"byte_size": read_bytes},
        refusals=(),
        unchecked=_UNCHECKED_ALL,
    )


# ------------------------------------------------------------------ шаг 21


def принять(
    path: str | os.PathLike[str],
    *,
    limits: IntakeLimits = APPROVED_LIMITS,
    source_name: str | None = None,
) -> IntakePassport:
    """Приём, при котором отказ — состояние, а не падение.

    ``accept_file`` бросает исключение, когда вход вовсе не является файлом:
    это ошибка вызывающего, и в строгом применении она обязана быть громкой.
    Но на общей дороге обработки недоступный файл — обычный исход, а не
    поломка станка, и у него должен быть паспорт наравне с прочими.

    Здесь такой случай превращается в отказ с причиной. Паспорт составляется
    всегда — даже когда о файле неизвестно почти ничего.
    """

    try:
        return accept_file(path, limits=limits, source_name=source_name)
    except IntakeError as отказ:
        declared = source_name if source_name is not None else Path(path).name
        return IntakePassport(
            schema_version=INTAKE_SCHEMA_VERSION,
            document_id=None,
            byte_size=None,
            source_name=declared,
            stored_name=safe_name(declared),
            suffix=PureWindowsPath(safe_name(declared)).suffix.lower(),
            trust="untrusted",
            limits=limits.as_json(),
            measurements={},
            refusals=(Refusal(отказ.code, str(отказ).split(": ", 1)[-1]),),
            unchecked=_UNCHECKED_ALL,
        )


def _check_positive_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IntakeError(
            "E_INVALID_MEASUREMENT",
            f"измерение {name} должно быть целым числом не меньше нуля",
        )
    return value


def check_limits(
    passport: IntakePassport,
    *,
    pages: int | None = None,
    container_depth: int | None = None,
    unpacked_bytes: int | None = None,
    duration_seconds: int | None = None,
    memory_bytes: int | None = None,
) -> IntakePassport:
    """Сверяет измеренные величины с пределами и возвращает новый паспорт.

    Величины измеряет тот, кто разбирает файл: приём их вычислить не может и не
    выдумывает. Переданное — проверяется, непереданное — остаётся в списке
    непроверенного и вместе с ним попадает в паспорт.

    Коэффициент сжатия вычисляется из распакованного объёма и размера файла и
    отдельным входным значением не принимается: иначе разбирающий мог бы
    объявить любое удобное число.

    Паспорт неизменяем: функция возвращает новый, а не правит прежний. Отказы
    накапливаются — уже вынесенный отказ не отменяется последующей проверкой.
    """

    limits = IntakeLimits(**dict(passport.limits))
    refusals = list(passport.refusals)
    measurements = dict(passport.measurements)
    unchecked = list(passport.unchecked)

    def measured(name: str, value: int) -> None:
        measurements[name] = value
        if name in unchecked:
            unchecked.remove(name)

    if pages is not None:
        value = _check_positive_int("pages", pages)
        measured("pages", value)
        if value > limits.max_pages:
            refusals.append(Refusal(
                "E_LIMIT_PAGES",
                f"страниц {value}, предел {limits.max_pages}"))

    if container_depth is not None:
        value = _check_positive_int("container_depth", container_depth)
        measured("container_depth", value)
        if value > limits.max_container_depth:
            refusals.append(Refusal(
                "E_LIMIT_CONTAINER_DEPTH",
                f"вложенность {value}, предел {limits.max_container_depth}"))

    if unpacked_bytes is not None:
        value = _check_positive_int("unpacked_bytes", unpacked_bytes)
        measured("unpacked_bytes", value)
        if value > limits.max_unpacked_bytes:
            refusals.append(Refusal(
                "E_LIMIT_UNPACKED_BYTES",
                f"распакованный объём {value} байт, "
                f"предел {limits.max_unpacked_bytes}"))
        # Коэффициент считаем только когда есть от чего считать. Целочисленное
        # деление вниз здесь безопасно: оно может лишь занизить коэффициент,
        # а сравнение строгое — «больше предела».
        if passport.byte_size:
            ratio = value // passport.byte_size
            measured("compression_ratio", ratio)
            if ratio > limits.max_compression_ratio:
                refusals.append(Refusal(
                    "E_LIMIT_COMPRESSION_RATIO",
                    f"коэффициент сжатия {ratio}, "
                    f"предел {limits.max_compression_ratio}"))

    if duration_seconds is not None:
        value = _check_positive_int("duration_seconds", duration_seconds)
        measured("duration_seconds", value)
        if value > limits.max_duration_seconds:
            refusals.append(Refusal(
                "E_LIMIT_DURATION",
                f"обработка заняла {value} с, предел {limits.max_duration_seconds}"))

    if memory_bytes is not None:
        value = _check_positive_int("memory_bytes", memory_bytes)
        measured("memory_bytes", value)
        if value > limits.max_memory_bytes:
            refusals.append(Refusal(
                "E_LIMIT_MEMORY",
                f"память {value} байт, предел {limits.max_memory_bytes}"))

    return IntakePassport(
        schema_version=passport.schema_version,
        document_id=passport.document_id,
        byte_size=passport.byte_size,
        source_name=passport.source_name,
        stored_name=passport.stored_name,
        suffix=passport.suffix,
        trust=passport.trust,
        limits=passport.limits,
        measurements=measurements,
        refusals=tuple(refusals),
        unchecked=tuple(unchecked),
        признаки=passport.признаки,
        расшифровка=passport.расшифровка,
    )


__all__ = [
    "APPROVED_LIMITS",
    "INTAKE_SCHEMA_VERSION",
    "KNOWN_LIMITATIONS",
    "IntakeError",
    "IntakeLimits",
    "IntakePassport",
    "Refusal",
    "accept_file",
    "check_limits",
    "safe_name",
    "принять",
]
