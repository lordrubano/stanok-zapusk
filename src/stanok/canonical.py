"""Каноническое байтовое представление записи версии ``record/1``.

Верхнеуровневые ключи выводятся в порядке схемы, поля внутри ``fields`` —
по возрастанию кодовых точек Unicode. В объекте отдельного поля сначала идут
``raw`` и ``value``, затем известные необязательные ключи ``currency`` и
``timezone``, а остальные необязательные ключи — по кодовым точкам. Вложенные
объекты также упорядочиваются по кодовым точкам. Порядок вставки во входные
словари поэтому на результат не влияет.

``raw`` и ``value`` всегда остаются двумя отдельными ключами. Нормализованное
числовое ``value`` из ``Decimal`` или ``int`` (кроме ``bool``) записывается
десятичной строкой; строка уже считается подготовленным точным значением и не
переформатируется. Это сохраняет, например, хвостовой ноль в ``"1234.50"``.

``date``, ``datetime`` и ``time`` переводятся стандартным ``isoformat()``.
У ``datetime`` и ``time`` со временем обязан быть UTC-offset. Для намеренно
наивного значения поле должно содержать явный маркер ``"timezone": null``;
маркер сохраняется в JSON. Строковые значения модуль не распознаёт и не
нормализует: они должны поступать уже в согласованном формате.

Результат — компактный UTF-8 JSON без хвостового перевода строки. Модуль не
выполняет Unicode-нормализацию и не содержит обратной сериализации.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence, Set
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any, Never


SCHEMA_VERSION = "record/1"
_TOP_LEVEL_KEYS = (
    "schema_version",
    "record_id",
    "source_anchor_ids",
    "template_version",
    "fields",
    "decision",
)
_FIELD_REQUIRED_KEYS = ("raw", "value")
_FIELD_OPTIONAL_KEYS = ("currency", "timezone")
_DECISIONS = frozenset({"accepted", "review", "rejected"})


class CanonicalError(ValueError):
    """Ошибка проверки или сериализации канонической записи."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _error(code: str, message: str) -> Never:
    raise CanonicalError(code, message)


def _reject_float(value: Any, path: str, active: set[int]) -> None:
    """Находит float до любых преобразований, в том числе в ключах объектов."""

    if isinstance(value, float):
        _error("E_FLOAT_NOT_ALLOWED", f"float запрещён: {path}")

    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            _error("E_CYCLIC_VALUE", f"циклическое значение запрещено: {path}")
        active.add(identity)
        try:
            for key, item in value.items():
                _reject_float(key, f"{path}.<ключ>", active)
                _reject_float(item, f"{path}.{key}", active)
        finally:
            active.remove(identity)
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        identity = id(value)
        if identity in active:
            _error("E_CYCLIC_VALUE", f"циклическое значение запрещено: {path}")
        active.add(identity)
        try:
            for index, item in enumerate(value):
                _reject_float(item, f"{path}[{index}]", active)
        finally:
            active.remove(identity)
    elif isinstance(value, Set):
        identity = id(value)
        if identity in active:
            _error("E_CYCLIC_VALUE", f"циклическое значение запрещено: {path}")
        active.add(identity)
        try:
            for item in value:
                _reject_float(item, f"{path}.<элемент>", active)
        finally:
            active.remove(identity)


def _require_key(mapping: Mapping[str, Any], key: str, path: str) -> Any:
    if key not in mapping:
        _error(
            "E_MISSING_REQUIRED_FIELD",
            f"отсутствует обязательное поле {path}.{key}",
        )
    return mapping[key]


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        _error("E_INVALID_FIELD_TYPE", f"{path} должно быть строкой")
    return value


def _decimal_text(value: Decimal, path: str) -> str:
    if not value.is_finite():
        _error("E_NON_FINITE_DECIMAL", f"NaN и бесконечность запрещены: {path}")
    return format(value, "f")


def _ordered_json_value(
    value: Any,
    path: str,
    *,
    exact_integers: bool = False,
    naive_time_marked: bool = False,
) -> Any:
    """Готовит поддерживаемое значение, не меняя текст и Unicode."""

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, float):
        _error("E_FLOAT_NOT_ALLOWED", f"float запрещён: {path}")
    if isinstance(value, Decimal):
        return _decimal_text(value, path)
    if isinstance(value, int):
        return str(value) if exact_integers else value
    if isinstance(value, datetime):
        if value.utcoffset() is None and not naive_time_marked:
            _error(
                "E_NAIVE_DATETIME_WITHOUT_MARKER",
                f"наивное время требует явного поля timezone=null: {path}",
            )
        return value.isoformat()
    if isinstance(value, time):
        if value.utcoffset() is None and not naive_time_marked:
            _error(
                "E_NAIVE_DATETIME_WITHOUT_MARKER",
                f"наивное время требует явного поля timezone=null: {path}",
            )
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            _error("E_INVALID_FIELD_TYPE", f"ключи объекта должны быть строками: {path}")
        return {
            key: _ordered_json_value(
                value[key],
                f"{path}.{key}",
                exact_integers=exact_integers,
                naive_time_marked=naive_time_marked,
            )
            for key in sorted(value)
        }
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return [
            _ordered_json_value(
                item,
                f"{path}[{index}]",
                exact_integers=exact_integers,
                naive_time_marked=naive_time_marked,
            )
            for index, item in enumerate(value)
        ]
    _error(
        "E_UNSUPPORTED_VALUE_TYPE",
        f"неподдерживаемый тип {type(value).__name__}: {path}",
    )


def _canonical_field(field: Any, field_name: str) -> dict[str, Any]:
    path = f"record.fields.{field_name}"
    if not isinstance(field, Mapping):
        _error("E_INVALID_FIELD_TYPE", f"{path} должно быть объектом")
    if not all(isinstance(key, str) for key in field):
        _error("E_INVALID_FIELD_TYPE", f"ключи {path} должны быть строками")

    for key in _FIELD_REQUIRED_KEYS:
        _require_key(field, key, path)

    # Само присутствие timezone=null является явным признаком отсутствия зоны.
    naive_time_marked = "timezone" in field and field["timezone"] is None
    result = {
        "raw": _ordered_json_value(
            field["raw"], f"{path}.raw", naive_time_marked=naive_time_marked
        ),
        "value": _ordered_json_value(
            field["value"],
            f"{path}.value",
            exact_integers=True,
            naive_time_marked=naive_time_marked,
        ),
    }
    optional = [key for key in _FIELD_OPTIONAL_KEYS if key in field]
    extensions = sorted(
        key
        for key in field
        if key not in _FIELD_REQUIRED_KEYS and key not in _FIELD_OPTIONAL_KEYS
    )
    for key in (*optional, *extensions):
        result[key] = _ordered_json_value(field[key], f"{path}.{key}")
    return result


def canonical_record_bytes(record: Any) -> bytes:
    """Проверяет запись ``record/1`` и возвращает её канонический UTF-8 JSON.

    Функция детерминирована относительно значений входа и не использует
    локаль, настройки Excel или системный перевод строки.
    """

    _reject_float(record, "record", set())
    if not isinstance(record, Mapping):
        _error("E_INVALID_RECORD_TYPE", "запись должна быть объектом")
    if not all(isinstance(key, str) for key in record):
        _error("E_INVALID_FIELD_TYPE", "ключи записи должны быть строками")

    for key in _TOP_LEVEL_KEYS:
        _require_key(record, key, "record")
    unknown = sorted(set(record).difference(_TOP_LEVEL_KEYS))
    if unknown:
        _error(
            "E_UNKNOWN_FIELD",
            "неизвестные поля записи: " + ", ".join(unknown),
        )

    schema_version = _require_string(
        record["schema_version"], "record.schema_version"
    )
    if schema_version != SCHEMA_VERSION:
        _error(
            "E_UNKNOWN_SCHEMA_VERSION",
            f"неизвестная версия схемы: {schema_version!r}",
        )

    record_id = _require_string(record["record_id"], "record.record_id")
    template_version = _require_string(
        record["template_version"], "record.template_version"
    )
    decision = _require_string(record["decision"], "record.decision")
    if decision not in _DECISIONS:
        _error("E_INVALID_DECISION", f"неизвестное решение записи: {decision!r}")

    anchor_ids = record["source_anchor_ids"]
    if not isinstance(anchor_ids, Sequence) or isinstance(
        anchor_ids, (str, bytes, bytearray)
    ):
        _error(
            "E_INVALID_FIELD_TYPE",
            "record.source_anchor_ids должно быть массивом строк",
        )
    canonical_anchor_ids = [
        _require_string(item, f"record.source_anchor_ids[{index}]")
        for index, item in enumerate(anchor_ids)
    ]

    fields = record["fields"]
    if not isinstance(fields, Mapping):
        _error("E_INVALID_FIELD_TYPE", "record.fields должно быть объектом")
    if not all(isinstance(key, str) for key in fields):
        _error("E_INVALID_FIELD_TYPE", "имена полей должны быть строками")
    canonical_fields = {
        name: _canonical_field(fields[name], name) for name in sorted(fields)
    }

    canonical = {
        "schema_version": schema_version,
        "record_id": record_id,
        "source_anchor_ids": canonical_anchor_ids,
        "template_version": template_version,
        "fields": canonical_fields,
        "decision": decision,
    }
    try:
        text = json.dumps(
            canonical,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        return text.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CanonicalError(
            "E_JSON_SERIALIZATION",
            "значение нельзя представить каноническим UTF-8 JSON",
        ) from exc
