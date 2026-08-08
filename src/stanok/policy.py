# -*- coding: utf-8 -*-
"""Политика шифрованных, повреждённых и макросодержащих файлов.

Шаг 23 плана. Нормативная основа — чертёж v3.0, раздел 14.1: «отдельная
политика макросов, вложений, шифрованных и повреждённых файлов».

Главное правило этого места: **отказ — это состояние, а не падение**. Ни один
разбор здесь не бросает исключение из-за свойств входа. Негодный файл — обычный
исход работы, а не поломка станка: у него своя причина, она попадает в паспорт
входа, и паспорт составляется в том числе на отвергнутый файл. Исключения
остаются только для ошибок в коде.

Второе правило: **пароль не остаётся нигде**. Ни в паспорте, ни в журнале, ни в
отчёте, ни в тексте отказа, ни в исключении. Поэтому пароль сюда передаётся не
строкой в настройках, а поставщиком — функцией, которую спрашивают в момент
надобности. В паспорт попадает только то, что расшифровка выполнялась и чем
кончилась, но не чем именно её выполняли.

Утверждено владельцем 04.08.2026:

* шифрованные — отвергать; приём пароля сделан и проверен на неутечку, но
  выключен до отдельного решения и до открытия раздела 14.3 (хранение секретов);
* макросодержащие — отвергать. Банки не выдают выписок с макросами, и макрос в
  выписке — признак подделки или нападения, а не обычного документа;
* повреждённые — отвергать. Неизвестное не равно правильному.

Станок макросы **никогда не исполняет**: он читает разметку, а не запускает код.
Отказ здесь не про исполнение, а про происхождение файла.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .archives import осмотреть, это_архив
from .intake import APPROVED_LIMITS, IntakeLimits, IntakePassport, Refusal


POLICY_VERSION = "intake-policy/1"

KNOWN_LIMITATIONS = (
    "Приём пароля выключен решением владельца: механизм сделан и проверен, но "
    "хранение паролей относится к разделу 14.3, который не открыт. Включать "
    "приём до этого нельзя — пароль негде держать безопасно.",
    "Вложения внутри документов (объекты OLE, приложенные файлы PDF) политикой "
    "пока не охвачены: их извлечение относится к адаптерам, шаги 26 и 28.",
    "Старые форматы doc и xls опознаются как контейнер OLE и проверяются на "
    "признаки макросов по содержимому. Полного разбора этого контейнера нет, "
    "поэтому такой файл без явных признаков макросов допускается лишь до "
    "адаптеров, которые обязаны разобрать его как следует.",
    "Антивирусной проверки нет: средство и политика не утверждены владельцем.",
)

# Подпись составного файла Microsoft (OLE2). В него завёрнуты и старые doc/xls,
# и зашифрованные книги нового формата.
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Имена внутри OLE записаны в UTF-16LE, поэтому и ищем их в таком виде.
_OLE_ENCRYPTED = "EncryptedPackage".encode("utf-16-le")
_OLE_VBA = "_VBA_PROJECT".encode("utf-16-le")
_OLE_MACROS = "Macros".encode("utf-16-le")

_PDF_MAGIC = b"%PDF-"
_PDF_ENCRYPT = b"/Encrypt"

_ZIP_VBA = "vbaProject.bin"
_ZIP_MACRO_TYPE = b"macroEnabled"


@dataclass(frozen=True, slots=True)
class Policy:
    """Утверждённая владельцем политика недоверенного входа.

    Значения не меняются исполнителем без нового решения владельца.
    """

    # Все значения ниже утверждены владельцем 04.08.2026.
    шифрованные: str = "отвергать"
    макросодержащие: str = "отвергать"
    повреждённые: str = "отвергать"
    приём_пароля_включён: bool = False

    def as_json(self) -> dict[str, object]:
        return {
            "версия": POLICY_VERSION,
            "шифрованные": self.шифрованные,
            "макросодержащие": self.макросодержащие,
            "повреждённые": self.повреждённые,
            "приём_пароля_включён": self.приём_пароля_включён,
        }


APPROVED_POLICY = Policy()
"""Утверждённая политика. Общая точка правды для всего станка."""


@dataclass(frozen=True, slots=True)
class PolicyVerdict:
    """Что политика нашла во входе и что из этого следует.

    ``признаки`` перечисляют найденное независимо от того, отвергнут файл или
    нет: наблюдение и решение — разные вещи, и смешивать их нельзя. Изменится
    политика — решение станет другим, а наблюдение останется тем же.
    """

    признаки: tuple[str, ...] = ()
    refusals: tuple[Refusal, ...] = ()
    расшифровка: str = "не требовалась"

    @property
    def допущен(self) -> bool:
        return not self.refusals

    def as_json(self) -> dict[str, object]:
        return {
            "признаки": list(self.признаки),
            "расшифровка": self.расшифровка,
            "refusals": [
                {"code": отказ.code, "message": отказ.message}
                for отказ in self.refusals
            ],
        }


def _зашифрованный_zip(data: bytes) -> bool:
    """Есть ли в архиве хотя бы один зашифрованный член."""
    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as архив:
            return any(член.flag_bits & 0x1 for член in архив.infolist())
    except (zipfile.BadZipFile, OSError, ValueError):
        # Нечитаемость — это повреждение, и разбирается она отдельно.
        return False


def _макросы_в_zip(data: bytes) -> bool:
    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as архив:
            for член in архив.infolist():
                if член.filename.rsplit("/", 1)[-1].lower() == _ZIP_VBA.lower():
                    return True
            # Тип содержимого объявляет книгу макросодержащей даже тогда, когда
            # самого vbaProject.bin в ней уже нет.
            try:
                типы = архив.read("[Content_Types].xml")
            except (KeyError, zipfile.BadZipFile, OSError, ValueError, RuntimeError):
                return False
            return _ZIP_MACRO_TYPE in типы
    except (zipfile.BadZipFile, OSError, ValueError):
        return False


def осмотреть_политикой(
    data: bytes,
    *,
    policy: Policy = APPROVED_POLICY,
    limits: IntakeLimits = APPROVED_LIMITS,
    пароль_поставщик=None,
) -> PolicyVerdict:
    """Применяет политику к содержимому файла.

    Ничего не бросает из-за свойств входа: любой негодный файл возвращается
    решением, а не исключением.

    ``пароль_поставщик`` — функция без доводов, отдающая пароль в момент
    надобности. Ни сам пароль, ни его длина, ни его признаки в вердикт не
    попадают. Поставщик спрашивается только если политика это позволяет.
    """

    признаки: list[str] = []
    отказы: list[Refusal] = []
    расшифровка = "не требовалась"

    if not data:
        отказы.append(Refusal("E_POLICY_BROKEN", "файл пуст и разбору не поддаётся"))
        return PolicyVerdict(("повреждение",), tuple(отказы), расшифровка)

    архив = это_архив(data[:4])
    ole = data.startswith(_OLE_MAGIC)
    pdf = data.startswith(_PDF_MAGIC)

    # ------------------------------------------------------------ шифрование
    зашифрован = False
    if архив:
        зашифрован = _зашифрованный_zip(data)
    elif ole:
        зашифрован = _OLE_ENCRYPTED in data
    elif pdf:
        зашифрован = _PDF_ENCRYPT in data

    if зашифрован:
        признаки.append("шифрование")
        if policy.шифрованные != "принимать" or not policy.приём_пароля_включён:
            расшифровка = "не выполнялась"
            отказы.append(Refusal(
                "E_POLICY_ENCRYPTED",
                "файл зашифрован; политика приёма шифрованных файлов выключена"))
        else:
            расшифровка = _попытаться_расшифровать(пароль_поставщик)
            if расшифровка != "выполнена":
                отказы.append(Refusal(
                    "E_POLICY_DECRYPT_FAILED",
                    "файл зашифрован, расшифровать не удалось"))

    # ----------------------------------------------------------- повреждение
    if архив:
        отчёт = осмотреть(data, limits=limits)
        сломан = [о for о in отчёт.refusals if о.code == "E_ARCHIVE_BROKEN"]
        if сломан and not зашифрован:
            признаки.append("повреждение")
            if policy.повреждённые != "принимать":
                отказы.append(Refusal(
                    "E_POLICY_BROKEN",
                    "файл повреждён и разбору не поддаётся"))
    elif pdf and b"%%EOF" not in data[-2048:]:
        признаки.append("повреждение")
        if policy.повреждённые != "принимать":
            отказы.append(Refusal(
                "E_POLICY_BROKEN", "PDF оборван: не найден признак конца файла"))
    elif not архив and not ole and not pdf:
        # Неопознанный формат повреждением не считается: он просто не наш.
        pass

    # -------------------------------------------------------------- макросы
    макросы = False
    if архив:
        макросы = _макросы_в_zip(data)
    elif ole:
        макросы = _OLE_VBA in data or _OLE_MACROS in data

    if макросы:
        признаки.append("макросы")
        if policy.макросодержащие != "принимать":
            отказы.append(Refusal(
                "E_POLICY_MACROS",
                "файл содержит макросы; политика их не допускает"))

    return PolicyVerdict(tuple(признаки), tuple(отказы), расшифровка)


def _попытаться_расшифровать(пароль_поставщик) -> str:
    """Спрашивает пароль и сообщает только исход.

    Пароль здесь живёт ровно столько, сколько нужно, и наружу не отдаётся ни в
    каком виде. Возвращается одно слово об исходе — из него нельзя вывести ни
    сам пароль, ни его длину.
    """

    if пароль_поставщик is None:
        return "пароль не предоставлен"
    try:
        пароль = пароль_поставщик()
    except Exception:  # noqa: BLE001 — поставщик чужой, его беды не наши
        return "пароль не получен"
    if not пароль:
        return "пароль не предоставлен"
    # Настоящая расшифровка появится вместе с адаптерами: разные форматы
    # расшифровываются по-разному, и делать это здесь значило бы разбирать
    # содержимое в месте, которое обязано только решать.
    del пароль
    return "не выполнялась"


def осмотреть_файл_политикой(
    path,
    *,
    policy: Policy = APPROVED_POLICY,
    limits: IntakeLimits = APPROVED_LIMITS,
    пароль_поставщик=None,
) -> PolicyVerdict:
    """Применяет политику к файлу. Отказ — состояние, а не падение."""

    файл = Path(path)
    try:
        if not файл.is_file():
            return PolicyVerdict(
                (), (Refusal("E_INTAKE_UNREADABLE", "файл недоступен"),))
        if файл.stat().st_size > limits.max_file_bytes:
            return PolicyVerdict(
                (), (Refusal(
                    "E_LIMIT_FILE_BYTES",
                    f"размер файла превышает предел {limits.max_file_bytes} байт"),))
        data = файл.read_bytes()
    except OSError as беда:
        return PolicyVerdict(
            (), (Refusal("E_INTAKE_UNREADABLE", f"файл не читается: {беда}"),))
    return осмотреть_политикой(
        data, policy=policy, limits=limits, пароль_поставщик=пароль_поставщик)


def внести_в_паспорт(passport: IntakePassport, verdict: PolicyVerdict) -> IntakePassport:
    """Кладёт наблюдения и решения политики в паспорт входа.

    Паспорт составляется и на отвергнутый файл: отказ — такой же результат
    приёма, как допуск, и он обязан быть предъявляемым. Прежние отказы не
    отменяются, а дополняются: годная проверка не отбеливает негодный файл.

    Пароль сюда не попадает никаким путём. В паспорт идёт только исход
    расшифровки одним словом.
    """

    return IntakePassport(
        schema_version=passport.schema_version,
        document_id=passport.document_id,
        byte_size=passport.byte_size,
        source_name=passport.source_name,
        stored_name=passport.stored_name,
        suffix=passport.suffix,
        trust=passport.trust,
        limits=passport.limits,
        measurements=passport.measurements,
        refusals=passport.refusals + verdict.refusals,
        unchecked=passport.unchecked,
        признаки=tuple(dict.fromkeys(passport.признаки + verdict.признаки)),
        расшифровка=verdict.расшифровка,
    )


__all__ = [
    "APPROVED_POLICY",
    "KNOWN_LIMITATIONS",
    "POLICY_VERSION",
    "Policy",
    "PolicyVerdict",
    "внести_в_паспорт",
    "осмотреть_политикой",
    "осмотреть_файл_политикой",
]
