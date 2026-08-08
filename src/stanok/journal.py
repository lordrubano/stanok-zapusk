"""Локальный добавляемый журнал запусков и событий с цепным SHA-256.

Каждая строка файла — один компактный JSON-объект в UTF-8, завершённый ``\n``.
Хеш записи связывает её содержимое, порядковый номер и хеш предыдущей записи.

Без внешнего якоря ``expected_head`` полная пересборка журнала не
обнаруживается; цепь доказывает только отсутствие частичной правки. В
частности, удаление целого корректного хвоста тоже можно доказать только при
наличии сохранённой снаружи вершины. Модуль не выдаёт цепной хеш за подпись или
за доказательство против владельца доступа на запись.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Never


CHAIN_START = "0" * 64

KNOWN_LIMITATIONS = (
    "Хранение вершины цепи вне журнала не решено: модуль отдаёт вершину через "
    "current_head и принимает её через expected_head, но где она хранится и чем "
    "заверяется — не определено. Решается вместе с классом поставки. "
    "Пока вершина не хранится снаружи, полная пересборка журнала тем, у кого "
    "есть доступ на запись, остаётся необнаружимой.",
)
"""Известные ограничения журнала.

Решение владельца от 03.08.2026: вопрос хранения вершины закрывается вместе с
классом поставки, а не в шаге 18. Запись оставлена явно, чтобы ограничение не
потерялось и не выдавалось за отсутствующее.
"""

_PAYLOAD_FIELDS = (
    "run_id",
    "stage_id",
    "attempt",
    "started_at",
    "finished_at",
    "duration_ms",
    "code_version",
    "model_version",
    "template_version",
    "reference_version",
    "policy_version",
    "input_count",
    "output_count",
    "memory_bytes",
    "cpu_ms",
    "external_pages",
    "result_code",
    "reason",
    "retry_id",
    "manifest_ref",
    "diagnostic_refs",
)
_CHAIN_FIELDS = ("sequence", "previous_hash", "hash")
_ENTRY_FIELDS = (
    "sequence",
    "previous_hash",
    *_PAYLOAD_FIELDS,
    "hash",
)
_RAW_FIELD_NAMES = frozenset(
    {
        "content",
        "contents",
        "base64",
        "binary",
        "blob",
        "body",
        "bytes",
        "data",
        "document",
        "document_base64",
        "document_body",
        "document_bytes",
        "document_content",
        "document_data",
        "document_text",
        "file_bytes",
        "file_content",
        "file_data",
        "ocr_text",
        "page_content",
        "payload",
        "raw",
        "raw_content",
        "raw_data",
        "raw_document",
        "raw_text",
        "source_content",
        "source_data",
        "source_text",
        "text",
        "содержимое",
        "содержимое_документа",
        "сырой_документ",
        "текст_документа",
    }
)
_RAW_FIELD_FRAGMENTS = (
    "document_content",
    "document_base64",
    "document_text",
    "document_body",
    "document_bytes",
    "document_data",
    "raw_content",
    "raw_document",
    "raw_text",
    "file_bytes",
    "page_content",
    "ocr_text",
    "source_content",
    "source_data",
    "source_text",
    "содержимое_документа",
    "текст_документа",
)
_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


class JournalError(ValueError):
    """Ошибка журнала с машинным кодом и номером испорченной записи."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        record_number: int | None = None,
    ) -> None:
        self.code = code
        self.record_number = record_number
        location = (
            f"запись {record_number}: " if record_number is not None else ""
        )
        super().__init__(f"{code}: {location}{message}")


class _DuplicateKeyError(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(key)


def _error(
    code: str,
    message: str,
    *,
    record_number: int | None = None,
) -> Never:
    raise JournalError(code, message, record_number=record_number)


def _is_array(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    )


def _normalised_field_name(name: str) -> str:
    return name.casefold().strip().replace("-", "_").replace(" ", "_")


def _is_raw_document_field(name: str) -> bool:
    normalised = _normalised_field_name(name)
    return normalised in _RAW_FIELD_NAMES or any(
        fragment in normalised for fragment in _RAW_FIELD_FRAGMENTS
    )


def _reject_raw_document_fields(
    value: Any,
    path: str,
    active: set[int],
    *,
    record_number: int | None,
) -> None:
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in active:
            return
        active.add(marker)
        try:
            for key, item in value.items():
                if isinstance(key, str) and _is_raw_document_field(key):
                    _error(
                        "E_RAW_DOCUMENT_CONTENT",
                        "сырое содержимое документа запрещено; "
                        f"разрешены только ссылки и идентификаторы: {path}.{key}",
                        record_number=record_number,
                    )
                if isinstance(key, str):
                    _reject_raw_document_fields(
                        item,
                        f"{path}.{key}",
                        active,
                        record_number=record_number,
                    )
        finally:
            active.remove(marker)
    elif _is_array(value):
        marker = id(value)
        if marker in active:
            return
        active.add(marker)
        try:
            for index, item in enumerate(value):
                _reject_raw_document_fields(
                    item,
                    f"{path}[{index}]",
                    active,
                    record_number=record_number,
                )
        finally:
            active.remove(marker)


def _canonical_value(
    value: Any,
    path: str,
    active: set[int],
    *,
    record_number: int | None,
) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        _require_utf8(value, path, record_number=record_number)
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        _error(
            "E_FLOAT_NOT_ALLOWED",
            f"float запрещён: {path}",
            record_number=record_number,
        )
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in active:
            _error(
                "E_CYCLIC_VALUE",
                f"циклическое значение запрещено: {path}",
                record_number=record_number,
            )
        if any(not isinstance(key, str) for key in value):
            _error(
                "E_INVALID_FIELD_TYPE",
                f"ключи объекта должны быть строками: {path}",
                record_number=record_number,
            )
        for key in value:
            _require_utf8(key, f"ключ {path}", record_number=record_number)
        active.add(marker)
        try:
            return {
                key: _canonical_value(
                    value[key],
                    f"{path}.{key}",
                    active,
                    record_number=record_number,
                )
                for key in sorted(value)
            }
        finally:
            active.remove(marker)
    if _is_array(value):
        marker = id(value)
        if marker in active:
            _error(
                "E_CYCLIC_VALUE",
                f"циклическое значение запрещено: {path}",
                record_number=record_number,
            )
        active.add(marker)
        try:
            return [
                _canonical_value(
                    item,
                    f"{path}[{index}]",
                    active,
                    record_number=record_number,
                )
                for index, item in enumerate(value)
            ]
        finally:
            active.remove(marker)
    _error(
        "E_UNSUPPORTED_VALUE_TYPE",
        f"неподдерживаемый тип {type(value).__name__}: {path}",
        record_number=record_number,
    )


def _require_utf8(
    value: str,
    path: str,
    *,
    record_number: int | None,
) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise JournalError(
            "E_INVALID_UTF8",
            f"{path} не представимо в UTF-8",
            record_number=record_number,
        ) from exc


def _require_nonempty_string(
    value: Any,
    path: str,
    *,
    record_number: int | None,
) -> str:
    if not isinstance(value, str):
        _error(
            "E_INVALID_FIELD_TYPE",
            f"{path} должно быть строкой",
            record_number=record_number,
        )
    _require_utf8(value, path, record_number=record_number)
    if not value or value != value.strip() or "\x00" in value or "\n" in value or "\r" in value:
        _error(
            "E_INVALID_FIELD_VALUE",
            f"{path} должно быть непустой однострочной строкой без внешних пробелов",
            record_number=record_number,
        )
    return value


def _require_nonnegative_integer(
    value: Any,
    path: str,
    *,
    positive: bool = False,
    record_number: int | None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _error(
            "E_INVALID_FIELD_TYPE",
            f"{path} должно быть целым числом",
            record_number=record_number,
        )
    minimum = 1 if positive else 0
    if value < minimum:
        condition = "положительным" if positive else "неотрицательным"
        _error(
            "E_INVALID_FIELD_VALUE",
            f"{path} должно быть {condition}",
            record_number=record_number,
        )
    return value


def _normalise_payload(
    record: Any,
    *,
    record_number: int | None = None,
) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        _error(
            "E_INVALID_FIELD_TYPE",
            "record должно быть объектом",
            record_number=record_number,
        )
    _reject_raw_document_fields(
        record,
        "record",
        set(),
        record_number=record_number,
    )
    if any(not isinstance(key, str) for key in record):
        _error(
            "E_INVALID_FIELD_TYPE",
            "ключи record должны быть строками",
            record_number=record_number,
        )

    missing = [field for field in _PAYLOAD_FIELDS if field not in record]
    if missing:
        _error(
            "E_MISSING_REQUIRED_FIELD",
            f"отсутствует обязательное поле record.{missing[0]}",
            record_number=record_number,
        )
    unknown = sorted(set(record).difference(_PAYLOAD_FIELDS))
    if unknown:
        _error(
            "E_UNKNOWN_FIELD",
            "неизвестные поля записи: " + ", ".join(unknown),
            record_number=record_number,
        )

    string_fields = (
        "run_id",
        "stage_id",
        "started_at",
        "finished_at",
        "code_version",
        "model_version",
        "template_version",
        "reference_version",
        "policy_version",
        "result_code",
        "retry_id",
        "manifest_ref",
    )
    normalised: dict[str, Any] = {}
    for field in string_fields:
        normalised[field] = _require_nonempty_string(
            record[field],
            f"record.{field}",
            record_number=record_number,
        )

    normalised["attempt"] = _require_nonnegative_integer(
        record["attempt"],
        "record.attempt",
        positive=True,
        record_number=record_number,
    )
    for field in (
        "duration_ms",
        "input_count",
        "output_count",
        "memory_bytes",
        "cpu_ms",
        "external_pages",
    ):
        normalised[field] = _require_nonnegative_integer(
            record[field],
            f"record.{field}",
            record_number=record_number,
        )

    reason = record["reason"]
    if not isinstance(reason, Mapping):
        _error(
            "E_UNSTRUCTURED_REASON",
            "record.reason должно быть объектом, а не свободным текстом",
            record_number=record_number,
        )
    if "code" not in reason:
        _error(
            "E_MISSING_REQUIRED_FIELD",
            "отсутствует обязательное поле record.reason.code",
            record_number=record_number,
        )
    _require_nonempty_string(
        reason["code"],
        "record.reason.code",
        record_number=record_number,
    )
    normalised["reason"] = _canonical_value(
        reason,
        "record.reason",
        set(),
        record_number=record_number,
    )

    diagnostic_refs = record["diagnostic_refs"]
    if not _is_array(diagnostic_refs):
        _error(
            "E_INVALID_FIELD_TYPE",
            "record.diagnostic_refs должно быть массивом ссылок",
            record_number=record_number,
        )
    normalised["diagnostic_refs"] = [
        _require_nonempty_string(
            reference,
            f"record.diagnostic_refs[{index}]",
            record_number=record_number,
        )
        for index, reference in enumerate(diagnostic_refs)
    ]

    return {field: normalised[field] for field in _PAYLOAD_FIELDS}


def нормализовать_событие(
    record,
    *,
    record_number: int | None = None,
) -> dict[str, Any]:
    """Свободная схема записи: та же цепь, но поля свои.

    Схема прогона (``_PAYLOAD_FIELDS``) закрыта и описывает **этап прогона**:
    попытку, длительности, версии. Действие оператора не прогон, и подставлять
    в эти поля выдуманные значения значило бы соврать в журнале ради того,
    чтобы в него попасть.

    Поэтому у журнала две схемы и одна цепь. Свободная схема требует немногого,
    но требует твёрдо: ключи — строки, значения канонизируемы, **сырого
    содержимого документа нет**. Последнее не послабление: журнал уходит наружу
    вместе с доказательным пакетом, и кусок документа в нём был бы утечкой, а
    не удобством.
    """
    if not isinstance(record, Mapping):
        _error(
            "E_INVALID_FIELD_TYPE",
            "запись журнала должна быть объектом",
            record_number=record_number,
        )
    if not record:
        _error(
            "E_MISSING_REQUIRED_FIELD",
            "пустая запись журнала свидетельством не является",
            record_number=record_number,
        )
    if any(not isinstance(ключ, str) for ключ in record):
        _error(
            "E_INVALID_FIELD_TYPE",
            "ключи записи должны быть строками",
            record_number=record_number,
        )
    занятые = set(record).intersection({"sequence", "previous_hash", "hash"})
    if занятые:
        _error(
            "E_UNKNOWN_FIELD",
            "поля цепи заняты самой цепью: " + ", ".join(sorted(занятые)),
            record_number=record_number,
        )
    _reject_raw_document_fields(record, "record", set(),
                                record_number=record_number)
    return {
        ключ: _canonical_value(
            record[ключ], f"record.{ключ}", set(), record_number=record_number
        )
        for ключ in sorted(record)
    }


def _validate_hash(
    value: Any,
    path: str,
    *,
    record_number: int | None = None,
) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _error(
            "E_INVALID_HASH",
            f"{path} должно быть SHA-256 в нижнем регистре",
            record_number=record_number,
        )
    return value


def _validate_sequence(
    sequence: Any,
    *,
    record_number: int | None = None,
) -> int:
    return _require_nonnegative_integer(
        sequence,
        "sequence",
        positive=True,
        record_number=record_number,
    )


def canonical_record_bytes(
    record: Mapping[str, Any],
    sequence: int,
    previous_hash: str,
    схема=None,
) -> bytes:
    """Возвращает канонические байты записи без её собственного хеша.

    ``схема`` — чем проверяются поля. Умолчание — схема прогона (шаг 18);
    для событий иного рода передаётся :func:`нормализовать_событие`. Способ
    укладки в байты при этом один и тот же, и он же считает хеш: две укладки
    дали бы две разные неизменности.
    """

    sequence = _validate_sequence(sequence)
    previous_hash = _validate_hash(previous_hash, "previous_hash")
    payload = _normalise_payload(record) if схема is None else схема(record)
    value = {
        "sequence": sequence,
        "previous_hash": previous_hash,
        **payload,
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def calculate_record_hash(
    record: Mapping[str, Any],
    sequence: int,
    previous_hash: str,
    схема=None,
) -> str:
    """Вычисляет детерминированный SHA-256 записи цепи."""

    return hashlib.sha256(
        canonical_record_bytes(record, sequence, previous_hash, схема)
    ).hexdigest()


def _entry_bytes(entry: Mapping[str, Any], схема=None) -> bytes:
    """Строка журнала в байтах. Порядок полей закреплён, а не случаен.

    У схемы прогона порядок задан перечнем полей; у свободной схемы полей
    заранее не знает никто, и порядок берётся тот, в каком их уложила сама
    схема, — она укладывает их по имени. Случайный порядок ключей сделал бы
    строку невоспроизводимой, а хеш — бессмысленным.
    """
    if схема is None:
        ordered = {field: entry[field] for field in _ENTRY_FIELDS}
    else:
        ordered = {
            "sequence": entry["sequence"],
            "previous_hash": entry["previous_hash"],
            **{ключ: значение for ключ, значение in entry.items()
               if ключ not in ("sequence", "previous_hash", "hash")},
            "hash": entry["hash"],
        }
    return json.dumps(
        ordered,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"недопустимая JSON-константа {value}")


def _decode_line(raw_line: bytes, record_number: int) -> Mapping[str, Any]:
    if not raw_line.endswith(b"\n"):
        _error(
            "E_TRUNCATED_RECORD",
            "последняя строка не завершена переводом строки",
            record_number=record_number,
        )
    payload = raw_line[:-1]
    if not payload:
        _error(
            "E_INVALID_JSON",
            "пустая строка не является записью JSON Lines",
            record_number=record_number,
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JournalError(
            "E_INVALID_UTF8",
            "строка не является корректным UTF-8",
            record_number=record_number,
        ) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError as exc:
        raise JournalError(
            "E_DUPLICATE_KEY",
            f"повторяющийся ключ JSON: {exc.key}",
            record_number=record_number,
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise JournalError(
            "E_INVALID_JSON",
            "строка не является корректным JSON",
            record_number=record_number,
        ) from exc
    if not isinstance(value, Mapping):
        _error(
            "E_INVALID_FIELD_TYPE",
            "запись JSON Lines должна быть объектом",
            record_number=record_number,
        )
    return value


def _local_path(path: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(path)
    except TypeError as exc:
        raise JournalError("E_INVALID_PATH", "путь журнала некорректен") from exc
    if isinstance(raw, bytes):
        try:
            raw = os.fsdecode(raw)
        except UnicodeError as exc:
            raise JournalError("E_INVALID_PATH", "путь журнала некорректен") from exc
    if raw.startswith(("\\\\", "//")):
        _error("E_NONLOCAL_PATH", "разрешён только локальный путь к журналу")
    return Path(raw)


def _path_lock(path: Path) -> threading.RLock:
    key = os.path.abspath(os.fspath(path))
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.RLock())


def _verify_path(path: Path, expected_head: str | None,
                 схема=None) -> tuple[str, int]:
    if expected_head is not None:
        expected_head = _validate_hash(expected_head, "expected_head")
    try:
        exists = path.exists()
        is_file = path.is_file()
    except OSError as exc:
        raise JournalError("E_IO", f"не удалось проверить путь журнала: {path}") from exc
    if not exists:
        _error("E_JOURNAL_NOT_FOUND", f"файл журнала не найден: {path}")
    if not is_file:
        _error("E_INVALID_PATH", f"путь журнала не является файлом: {path}")

    previous_hash = CHAIN_START
    count = 0
    try:
        with path.open("rb") as stream:
            for record_number, raw_line in enumerate(stream, start=1):
                count = record_number
                entry = _decode_line(raw_line, record_number)
                if any(not isinstance(key, str) for key in entry):
                    _error(
                        "E_INVALID_FIELD_TYPE",
                        "ключи записи должны быть строками",
                        record_number=record_number,
                    )
                ожидаемые = (_ENTRY_FIELDS if схема is None
                             else ("sequence", "previous_hash", "hash"))
                missing = [field for field in ожидаемые if field not in entry]
                if missing:
                    _error(
                        "E_MISSING_REQUIRED_FIELD",
                        f"отсутствует обязательное поле record.{missing[0]}",
                        record_number=record_number,
                    )
                if схема is None:
                    unknown = sorted(set(entry).difference(_ENTRY_FIELDS))
                    if unknown:
                        _error(
                            "E_UNKNOWN_FIELD",
                            "неизвестные поля записи: " + ", ".join(unknown),
                            record_number=record_number,
                        )

                sequence = _validate_sequence(
                    entry["sequence"], record_number=record_number
                )
                if sequence != record_number:
                    _error(
                        "E_SEQUENCE_MISMATCH",
                        f"ожидался номер {record_number}, получен {sequence}",
                        record_number=record_number,
                    )
                stored_previous = _validate_hash(
                    entry["previous_hash"],
                    "record.previous_hash",
                    record_number=record_number,
                )
                if not hmac.compare_digest(stored_previous, previous_hash):
                    _error(
                        "E_PREVIOUS_HASH_MISMATCH",
                        "хеш предыдущей записи не совпадает с вершиной префикса",
                        record_number=record_number,
                    )

                if схема is None:
                    payload = _normalise_payload(
                        {field: entry[field] for field in _PAYLOAD_FIELDS},
                        record_number=record_number,
                    )
                else:
                    payload = схема(
                        {ключ: значение for ключ, значение in entry.items()
                         if ключ not in ("sequence", "previous_hash", "hash")},
                        record_number=record_number,
                    )
                stored_hash = _validate_hash(
                    entry["hash"],
                    "record.hash",
                    record_number=record_number,
                )
                actual_hash = hashlib.sha256(
                    canonical_record_bytes(payload, sequence, stored_previous,
                                           схема)
                ).hexdigest()
                if not hmac.compare_digest(stored_hash, actual_hash):
                    _error(
                        "E_HASH_MISMATCH",
                        "собственный хеш записи не совпадает с её содержимым",
                        record_number=record_number,
                    )
                previous_hash = stored_hash
    except JournalError:
        raise
    except OSError as exc:
        raise JournalError("E_IO", f"не удалось прочитать журнал: {path}") from exc

    if expected_head is not None and not hmac.compare_digest(
        previous_hash, expected_head
    ):
        _error(
            "E_HEAD_MISMATCH",
            f"вершина цепи не совпала после проверки {count} записей",
            record_number=count if count else None,
        )
    return previous_hash, count


def verify_journal(
    path: str | os.PathLike[str],
    expected_head: str | None = None,
    *,
    схема=None,
) -> str:
    """Проверяет журнал от начала и возвращает текущую вершину цепи."""

    journal_path = _local_path(path)
    with _path_lock(journal_path):
        head, _ = _verify_path(journal_path, expected_head, схема)
    return head


def current_head(path: str | os.PathLike[str]) -> str:
    """Проверяет журнал и возвращает его текущую вершину."""

    return verify_journal(path)


def _хвост_цепи(path: Path, схема) -> tuple[str, int]:
    """Вершина и число записей по последней строке, без чтения всего журнала.

    Полная проверка при каждом добавлении стоит квадрата: на восьмистах
    событиях это пятьдесят секунд, на десяти тысячах — часы. При этом она
    ничего не добавляет к неизменности: подделка обнаруживается при **чтении**
    журнала и при закреплении вершины, а не в тот миг, когда рядом дописали
    строку.

    Последняя строка всё же проверяется на собственный хеш: пристроить цепь к
    строке, которая сама себе не соответствует, значило бы продолжить подделку
    и заверить её своей рукой.
    """
    последняя, номер = None, 0
    with path.open("rb") as поток:
        for номер, строка in enumerate(поток, start=1):
            if строка.strip():
                последняя = строка
    if последняя is None:
        return CHAIN_START, 0
    entry = _decode_line(последняя, номер)
    for поле in ("sequence", "previous_hash", "hash"):
        if поле not in entry:
            _error("E_MISSING_REQUIRED_FIELD",
                   f"отсутствует обязательное поле record.{поле}",
                   record_number=номер)
    sequence = _validate_sequence(entry["sequence"], record_number=номер)
    previous = _validate_hash(entry["previous_hash"], "record.previous_hash",
                              record_number=номер)
    stored = _validate_hash(entry["hash"], "record.hash", record_number=номер)
    if схема is None:
        payload = _normalise_payload(
            {поле: entry[поле] for поле in _PAYLOAD_FIELDS}, record_number=номер)
    else:
        payload = схема({ключ: значение for ключ, значение in entry.items()
                         if ключ not in ("sequence", "previous_hash", "hash")},
                        record_number=номер)
    свой = hashlib.sha256(
        canonical_record_bytes(payload, sequence, previous, схема)).hexdigest()
    if not hmac.compare_digest(stored, свой):
        _error("E_HASH_MISMATCH",
               "собственный хеш последней записи не совпадает с её содержимым",
               record_number=номер)
    return stored, sequence


def append_record(
    path: str | os.PathLike[str],
    record: Mapping[str, Any],
    *,
    схема=None,
    доверяя_хвосту: bool = False,
) -> str:
    """Добавляет одну запись и возвращает новую вершину цепи.

    ``схема`` — чем проверяются поля записи. По умолчанию схема прогона
    (шаг 18); :func:`нормализовать_событие` даёт свободную — для событий иного
    рода. Цепь при этом одна: два журнала со своими цепями рано или поздно
    разошлись бы в понимании того, что такое неизменность.

    ``доверяя_хвосту`` — не перечитывать весь журнал ради одной строки.
    Умолчание прежнее: полная проверка. Быстрый путь берёт вершину из последней
    строки, проверив её собственный хеш, и годится там, где записей много, а
    подделка всё равно ловится при чтении и при закреплении вершины.
    """

    journal_path = _local_path(path)
    payload = _normalise_payload(record) if схема is None else схема(record)
    with _path_lock(journal_path):
        try:
            exists = journal_path.exists()
        except OSError as exc:
            raise JournalError(
                "E_IO", f"не удалось проверить путь журнала: {journal_path}"
            ) from exc
        if exists:
            previous_hash, count = (
                _хвост_цепи(journal_path, схема) if доверяя_хвосту
                else _verify_path(journal_path, None, схема))
        else:
            previous_hash, count = CHAIN_START, 0
        sequence = count + 1
        record_hash = calculate_record_hash(payload, sequence,
                                            previous_hash, схема)
        entry = {
            "sequence": sequence,
            "previous_hash": previous_hash,
            **payload,
            "hash": record_hash,
        }
        line = _entry_bytes(entry, схема) + b"\n"
        try:
            with journal_path.open("ab") as stream:
                written = stream.write(line)
                if written != len(line):
                    _error("E_IO", "запись журнала добавлена не полностью")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise JournalError(
                "E_IO", f"не удалось добавить запись в журнал: {journal_path}"
            ) from exc
    return record_hash


__all__ = [
    "CHAIN_START",
    "JournalError",
    "append_record",
    "calculate_record_hash",
    "canonical_record_bytes",
    "current_head",
    "нормализовать_событие",
    "verify_journal",
]
