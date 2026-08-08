# -*- coding: utf-8 -*-
"""Осмотр архивов: защита от бомб и от обхода каталогов.

Шаг 22 плана. Нормативная основа — чертёж v3.0, раздел 14.1: «блокировка XXE,
внешних сущностей, обхода каталогов и zip-бомб».

Модуль **осматривает** архив, но ничего не распаковывает на диск. Ни один байт
не пишется за пределы памяти, поэтому обход каталогов здесь не может состояться
даже при ошибке в проверке: писать некуда. Проверка имён нужна затем, чтобы
негодный архив был отвергнут до того, как его получит распаковщик из будущих
шагов.

Три вещи, на которых обычно ломаются защиты от бомб:

1. **Объявленному размеру верить нельзя.** В заголовке архива лежит число,
   которое туда написал тот, кто архив собрал. Бомба объявляет скромный размер
   и разворачивается в гигабайты. Поэтому объём считается по фактически
   прочитанным байтам, а чтение обрывается на пределе.
2. **Расширению верить нельзя.** Формат определяется по первым байтам, а не по
   имени: `.txt` бывает архивом, а `.zip` — нет.
3. **Вложенность.** Архив в архиве в архиве разворачивается лавиной при скромном
   исходном размере. Глубина считается и ограничивается.

Отдельного предела на число членов архива нет намеренно: их количество уже
ограничено пределом размера файла. Оглавление архива само занимает место, и в
утверждённые 100 МБ помещается не больше полутора миллионов записей, перебор
которых занимает секунды, а не минуты.

Чего здесь нет: XXE и внешних сущностей. Это разбор XML, он придёт с адаптерами
нативных маршрутов (шаг 26), а не с осмотром контейнера. Названо прямо, чтобы
пункт 14.1 не выглядел закрытым целиком.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from .deadline import СрокИстёк, место as срок_места
from .intake import APPROVED_LIMITS, IntakeLimits, Refusal


ARCHIVE_REPORT_VERSION = "archive-report/1"

KNOWN_LIMITATIONS = (
    "XXE и внешние сущности здесь не проверяются: это разбор XML, он относится "
    "к адаптерам нативных маршрутов (шаг 26), а не к осмотру контейнера.",
    "Из архивных форматов осматривается только ZIP и построенные на нём "
    "рабочие форматы. RAR, 7z и tar.gz не осматриваются и потому не "
    "допускаются: неосмотренный контейнер не считается безопасным.",
    "Повреждённые и зашифрованные архивы обнаруживаются, но политика для них "
    "не утверждена — это шаг 23. Пока такой архив отвергается.",
)

# Первые байты ZIP. Пустой архив и архив с пометкой о разделении томов имеют
# свои подписи, и все три обязаны узнаваться: иначе бомба переоденется.
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

_CHUNK = 1 << 16


@dataclass(frozen=True, slots=True)
class ArchiveReport:
    """Что осмотр узнал об архиве."""

    schema_version: str
    формат: str
    members: int
    unpacked_bytes: int
    depth: int
    refusals: tuple[Refusal, ...] = ()

    @property
    def безопасен(self) -> bool:
        return not self.refusals

    def as_json(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "формат": self.формат,
            "members": self.members,
            "unpacked_bytes": self.unpacked_bytes,
            "depth": self.depth,
            "refusals": [
                {"code": отказ.code, "message": отказ.message}
                for отказ in self.refusals
            ],
        }


def это_архив(head: bytes) -> bool:
    """Узнаёт архив по первым байтам, а не по имени файла."""

    return any(head.startswith(подпись) for подпись in _ZIP_MAGIC)


def опасное_имя(name: str) -> str | None:
    """Причина, по которой имя члена архива нельзя принять, либо None.

    Имя внутри архива — это указание, куда распаковщик положит файл. Через него
    уходят за пределы каталога назначения: `../../` в имени, абсолютный путь,
    буква диска. Здесь такое имя отвергается, а не исправляется: исправленное
    имя скрыло бы попытку, а попытка — это признак нападения, и она обязана быть
    видимой.
    """

    if not name:
        return "пустое имя"
    if "\x00" in name:
        return "имя содержит нулевой байт"
    # Обратный слэш в ZIP запрещён спецификацией, но встречается у тех, кто
    # собирал архив вручную, и на Windows он разделитель пути.
    приведённое = name.replace("\\", "/")
    if приведённое.startswith("/"):
        return "абсолютный путь"
    if PureWindowsPath(name).drive or PureWindowsPath(приведённое).drive:
        return "путь с буквой диска"
    части = PurePosixPath(приведённое).parts
    if any(часть == ".." for часть in части):
        return "выход в родительский каталог"
    return None


def _ссылка(member: zipfile.ZipInfo) -> bool:
    """Член архива является символической ссылкой.

    Ссылка внутри архива уводит распаковщик куда угодно, оставаясь безобидной
    на вид: имя её проверку на обход каталогов проходит, а цель — нет.
    """

    return (member.external_attr >> 16) & 0o170000 == 0o120000


def _зашифрован(member: zipfile.ZipInfo) -> bool:
    return bool(member.flag_bits & 0x1)


def осмотреть(
    data: bytes,
    *,
    limits: IntakeLimits = APPROVED_LIMITS,
    depth: int = 1,
    бюджет: int | None = None,
    срок=None,
) -> ArchiveReport:
    """Осматривает архив в памяти, ничего не распаковывая на диск.

    ``бюджет`` — сколько распакованных байт ещё позволено прочитать. Он общий
    на весь осмотр, включая вложенные архивы: иначе каждый вложенный уровень
    получал бы предел заново, и лавина проходила бы по частям.
    """

    if бюджет is None:
        бюджет = limits.max_unpacked_bytes
    # Срок общий на весь осмотр, как и бюджет объёма: вложенный архив получает
    # тот же самый, а не заводит себе новый. Иначе лавина, проходящая по
    # частям, обошла бы срок так же, как обошла бы объём.
    свой = срок if срок is not None else срок_места("разбор архива")

    отказы: list[Refusal] = []
    if depth > limits.max_container_depth:
        return ArchiveReport(
            ARCHIVE_REPORT_VERSION, "zip", 0, 0, depth,
            (Refusal("E_LIMIT_CONTAINER_DEPTH",
                     f"вложенность {depth}, предел {limits.max_container_depth}"),))

    try:
        архив = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError) as порча:
        return ArchiveReport(
            ARCHIVE_REPORT_VERSION, "zip", 0, 0, depth,
            (Refusal("E_ARCHIVE_BROKEN", f"архив не читается: {порча}"),))

    прочитано = 0
    глубина = depth
    члены = архив.infolist()

    with архив:
        try:
            for member in члены:
                свой.проверить()
                имя = member.filename
                беда = опасное_имя(имя)
                if беда:
                    отказы.append(Refusal("E_ARCHIVE_PATH_TRAVERSAL", f"{имя}: {беда}"))
                    continue
                if _ссылка(member):
                    отказы.append(Refusal(
                        "E_ARCHIVE_SYMLINK", f"{имя}: ссылка внутри архива"))
                    continue
                if _зашифрован(member):
                    отказы.append(Refusal(
                        "E_ARCHIVE_ENCRYPTED",
                        f"{имя}: зашифрован; политика шифрованных файлов — шаг 23"))
                    continue
                if member.is_dir():
                    continue

                вложенные_байты = bytearray()
                запас = бюджет - прочитано
                try:
                    with архив.open(member) as поток:
                        while True:
                            свой.проверить()
                            кусок = поток.read(_CHUNK)
                            if not кусок:
                                break
                            прочитано += len(кусок)
                            if прочитано > бюджет:
                                отказы.append(Refusal(
                                    "E_LIMIT_UNPACKED_BYTES",
                                    f"{имя}: распакованный объём превысил предел "
                                    f"{limits.max_unpacked_bytes} байт; "
                                    "чтение прекращено"))
                                return ArchiveReport(
                                    ARCHIVE_REPORT_VERSION, "zip", len(члены),
                                    бюджет, глубина, tuple(отказы))
                            if len(вложенные_байты) < запас:
                                вложенные_байты.extend(кусок)
                except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as порча:
                    отказы.append(Refusal(
                        "E_ARCHIVE_BROKEN", f"{имя}: член не читается ({порча})"))
                    continue

                if это_архив(bytes(вложенные_байты[:4])):
                    вложенный = осмотреть(
                        bytes(вложенные_байты), limits=limits, depth=depth + 1,
                        бюджет=бюджет - прочитано, срок=свой)
                    прочитано += вложенный.unpacked_bytes
                    глубина = max(глубина, вложенный.depth)
                    отказы.extend(вложенный.refusals)

        except СрокИстёк as вышел:
            # Осмотр архива отказывает так же, как отказывает по объёму: причиной
            # в отчёте, а не исключением наружу. Уже найденные отказы при этом не
            # теряются — вышедший срок добавляется к ним, а не отменяет их.
            отказы.append(вышел.отказ)
            return ArchiveReport(
                ARCHIVE_REPORT_VERSION, "zip", len(члены), прочитано, глубина,
                tuple(отказы))

    return ArchiveReport(
        ARCHIVE_REPORT_VERSION, "zip", len(члены), прочитано, глубина,
        tuple(отказы))


def осмотреть_файл(path, *, limits: IntakeLimits = APPROVED_LIMITS) -> ArchiveReport:
    """Осматривает файл, если он оказался архивом.

    Формат определяется по первым байтам: расширение может лгать, и книга Excel
    с именем ``письмо.txt`` обязана быть узнана архивом.

    Предел размера проверяется здесь повторно, хотя приём его уже проверил:
    осмотр берёт файл в память целиком, и полагаться на то, что вызывающий не
    забыл принять файл как положено, здесь нельзя.
    """

    файл = Path(path)
    if not файл.is_file():
        return ArchiveReport(
            ARCHIVE_REPORT_VERSION, "не архив", 0, 0, 0,
            (Refusal("E_INTAKE_UNREADABLE", "файл недоступен"),))
    if файл.stat().st_size > limits.max_file_bytes:
        return ArchiveReport(
            ARCHIVE_REPORT_VERSION, "не осмотрен", 0, 0, 0,
            (Refusal("E_LIMIT_FILE_BYTES",
                     f"размер файла превышает предел {limits.max_file_bytes} байт; "
                     "архив в память не берётся"),))

    with файл.open("rb") as поток:
        head = поток.read(4)
    if not это_архив(head):
        return ArchiveReport(ARCHIVE_REPORT_VERSION, "не архив", 0, 0, 0, ())
    return осмотреть(файл.read_bytes(), limits=limits)


__all__ = [
    "ARCHIVE_REPORT_VERSION",
    "KNOWN_LIMITATIONS",
    "ArchiveReport",
    "осмотреть",
    "осмотреть_файл",
    "опасное_имя",
    "это_архив",
]
