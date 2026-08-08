"""Независимый обратный путь для канонической записи ``record/1``.

Модуль намеренно заново описывает схему и преобразование исходных значений к
виду, пригодному для сравнения. Из прямого пути используется только финальная
функция получения канонических байтов: её результат нужен как SHA-256-след, но
не участвует в решении о равенстве записей.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal
from hashlib import sha256
from typing import Any, Never

from .canonical import canonical_record_bytes


# Это самостоятельное описание схемы обратного пути, а не переиспользование
# констант прямого сериализатора.
_SUPPORTED_SCHEMA = "record/1"
_RECORD_MEMBERS = frozenset(
    {
        "schema_version",
        "record_id",
        "source_anchor_ids",
        "template_version",
        "fields",
        "decision",
    }
)
_REQUIRED_FIELD_MEMBERS = frozenset({"raw", "value"})
_KNOWN_DECISIONS = frozenset({"accepted", "review", "rejected"})

VALUE_MISMATCH = "value_mismatch"
MISSING_VALUE = "missing"
EXTRA_VALUE = "extra"
TYPE_MISMATCH = "type_mismatch"


class ReverseError(ValueError):
    """Ошибка независимого разбора или подготовки видимого сравнения."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _error(code: str, message: str) -> Never:
    raise ReverseError(code, message)


@dataclass(frozen=True)
class _AbsentValue:
    """Явная метка отсутствия, отличимая от законного значения ``None``."""

    def __repr__(self) -> str:
        return "<отсутствует>"

    def __str__(self) -> str:
        return "<отсутствует>"


ABSENT = _AbsentValue()


@dataclass(frozen=True)
class Difference:
    """Одно видимое расхождение между ожидаемой и восстановленной записью."""

    path: str
    expected: Any
    actual: Any
    kind: str

    @property
    def received(self) -> Any:
        """Синоним ``actual`` для вызывающего кода и операторских отчётов."""

        return self.actual

    @property
    def difference_type(self) -> str:
        """Машинное обозначение характера различия."""

        return self.kind


@dataclass(frozen=True)
class ComparisonResult:
    """Результат видимого сравнения с неавторитетными SHA-256-следами."""

    differences: list[Difference]
    source_sha256: str
    restored_sha256: str

    @property
    def is_equal(self) -> bool:
        """Равенство определяется только полным видимым сравнением."""

        return not self.differences

    @property
    def equal(self) -> bool:
        """Краткий синоним ``is_equal``."""

        return self.is_equal

    @property
    def hashes_match(self) -> bool:
        return self.source_sha256 == self.restored_sha256

    @property
    def hash_conflict(self) -> bool:
        """Хеши совпали, хотя видимое сравнение обнаружило расхождение."""

        return self.hashes_match and bool(self.differences)

    @property
    def report(self) -> str:
        """Человекочитаемый результат, пригодный для показа оператору."""

        return format_comparison(self)

    def __bool__(self) -> bool:
        """Истина означает видимое равенство, а не равенство хешей."""

        return self.is_equal


def _reject_json_constant(token: str) -> Never:
    _error("E_INVALID_JSON_NUMBER", f"недопустимое число JSON: {token}")


def _parse_json_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        _error("E_INVALID_JSON_NUMBER", f"число JSON вне допустимого диапазона: {token}")
    return value


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _error("E_DUPLICATE_KEY", f"ключ JSON повторён: {key!r}")
        result[key] = value
    return result


def _require_member(mapping: Mapping[str, Any], member: str, path: str) -> Any:
    if member not in mapping:
        location = f"{path}.{member}" if path else member
        _error(
            "E_MISSING_REQUIRED_FIELD",
            f"отсутствует обязательное поле {location}",
        )
    return mapping[member]


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        _error("E_INVALID_FIELD_TYPE", f"{path} должно быть строкой")
    return value


def _validate_restored_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        _error("E_INVALID_RECORD_TYPE", "корень записи должен быть объектом JSON")

    # Версия определяет смысл остальных полей, поэтому проверяется первой даже
    # у неполной записи неизвестной схемы.
    version = _require_string(
        _require_member(value, "schema_version", ""),
        "schema_version",
    )
    if version != _SUPPORTED_SCHEMA:
        _error(
            "E_UNKNOWN_SCHEMA_VERSION",
            f"неизвестная версия схемы: {version!r}",
        )

    for member in _RECORD_MEMBERS:
        _require_member(value, member, "")
    unknown = sorted(set(value).difference(_RECORD_MEMBERS))
    if unknown:
        _error(
            "E_UNKNOWN_FIELD",
            "неизвестные поля записи: " + ", ".join(unknown),
        )

    _require_string(value["record_id"], "record_id")
    _require_string(value["template_version"], "template_version")
    decision = _require_string(value["decision"], "decision")
    if decision not in _KNOWN_DECISIONS:
        _error("E_INVALID_DECISION", f"неизвестное решение записи: {decision!r}")

    anchors = value["source_anchor_ids"]
    if not isinstance(anchors, list):
        _error(
            "E_INVALID_FIELD_TYPE",
            "source_anchor_ids должно быть массивом строк",
        )
    for index, anchor in enumerate(anchors):
        _require_string(anchor, f"source_anchor_ids[{index}]")

    fields = value["fields"]
    if not isinstance(fields, dict):
        _error("E_INVALID_FIELD_TYPE", "fields должно быть объектом JSON")
    for field_name, field in fields.items():
        field_path = f"fields.{field_name}"
        if not isinstance(field, dict):
            _error("E_INVALID_FIELD_TYPE", f"{field_path} должно быть объектом JSON")
        for member in _REQUIRED_FIELD_MEMBERS:
            _require_member(field, member, field_path)

    return value


def parse_canonical_record(payload: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Восстанавливает и самостоятельно проверяет запись из UTF-8 JSON-байтов.

    Порядок ключей во входном JSON не имеет значения. Повторяющиеся ключи не
    принимаются: иначе одно видимое значение могло бы незаметно затереть другое.
    """

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        _error("E_INVALID_CANONICAL_BYTES", "ожидались канонические байты")
    try:
        text = bytes(payload).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReverseError(
            "E_INVALID_UTF8",
            "каноническая запись не является корректным UTF-8",
        ) from exc

    try:
        restored = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
            parse_float=_parse_json_float,
        )
    except ReverseError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ReverseError(
            "E_INVALID_JSON",
            "канонические байты не содержат корректную запись JSON",
        ) from exc

    return _validate_restored_record(restored)


def _decimal_for_comparison(value: Decimal, path: str) -> str:
    if not value.is_finite():
        _error(
            "E_NON_FINITE_DECIMAL",
            f"NaN и бесконечность нельзя сравнить как точное значение: {path}",
        )
    # format(..., "f") выбран здесь самостоятельно: он сохраняет масштаб
    # Decimal и, следовательно, видимый хвостовой ноль в денежных значениях.
    return format(value, "f")


def _source_value(
    value: Any,
    path: str,
    *,
    integers_are_exact: bool,
    active: set[int],
) -> Any:
    """Независимо приводит исходное значение к видимому JSON-представлению."""

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, Decimal):
        return _decimal_for_comparison(value, path)
    if isinstance(value, float):
        _error("E_FLOAT_NOT_ALLOWED", f"float запрещён в исходной записи: {path}")
    if isinstance(value, int):
        return str(value) if integers_are_exact else value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()

    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            _error("E_CYCLIC_VALUE", f"циклическое значение запрещено: {path}")
        if not all(isinstance(key, str) for key in value):
            _error(
                "E_INVALID_FIELD_TYPE",
                f"ключи объекта должны быть строками: {path}",
            )
        active.add(identity)
        try:
            return {
                key: _source_value(
                    item,
                    f"{path}.{key}" if path else key,
                    integers_are_exact=integers_are_exact,
                    active=active,
                )
                for key, item in value.items()
            }
        finally:
            active.remove(identity)

    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    ):
        identity = id(value)
        if identity in active:
            _error("E_CYCLIC_VALUE", f"циклическое значение запрещено: {path}")
        active.add(identity)
        try:
            return [
                _source_value(
                    item,
                    f"{path}[{index}]",
                    integers_are_exact=integers_are_exact,
                    active=active,
                )
                for index, item in enumerate(value)
            ]
        finally:
            active.remove(identity)

    _error(
        "E_UNSUPPORTED_VALUE_TYPE",
        f"неподдерживаемый тип {type(value).__name__}: {path}",
    )


def _source_record_for_comparison(record: Any) -> Any:
    """Готовит ожидаемую сторону без вызова кода прямой нормализации."""

    if not isinstance(record, Mapping):
        return _source_value(record, "", integers_are_exact=False, active=set())
    if not all(isinstance(key, str) for key in record):
        _error("E_INVALID_FIELD_TYPE", "ключи исходной записи должны быть строками")

    active = {id(record)}
    result: dict[str, Any] = {}
    for key, value in record.items():
        if key != "fields" or not isinstance(value, Mapping):
            result[key] = _source_value(
                value,
                key,
                integers_are_exact=False,
                active=active,
            )
            continue

        fields_result: dict[str, Any] = {}
        for field_name, field in value.items():
            field_path = f"fields.{field_name}"
            if not isinstance(field_name, str):
                _error(
                    "E_INVALID_FIELD_TYPE",
                    "имена полей исходной записи должны быть строками",
                )
            if not isinstance(field, Mapping):
                fields_result[field_name] = _source_value(
                    field,
                    field_path,
                    integers_are_exact=False,
                    active=active,
                )
                continue
            if not all(isinstance(member, str) for member in field):
                _error(
                    "E_INVALID_FIELD_TYPE",
                    f"ключи {field_path} должны быть строками",
                )

            field_identity = id(field)
            if field_identity in active:
                _error(
                    "E_CYCLIC_VALUE",
                    f"циклическое значение запрещено: {field_path}",
                )
            active.add(field_identity)
            try:
                fields_result[field_name] = {
                    member: _source_value(
                        member_value,
                        f"{field_path}.{member}",
                        integers_are_exact=member == "value",
                        active=active,
                    )
                    for member, member_value in field.items()
                }
            finally:
                active.remove(field_identity)
        result[key] = fields_result
    return result


def _path(parent: str, member: str) -> str:
    return f"{parent}.{member}" if parent else member


def _collect_differences(
    expected: Any,
    actual: Any,
    path: str,
    output: list[Difference],
) -> None:
    if isinstance(expected, Mapping) and isinstance(actual, Mapping):
        expected_keys = set(expected)
        actual_keys = set(actual)
        for member in sorted(expected_keys - actual_keys):
            output.append(
                Difference(
                    _path(path, member),
                    expected[member],
                    ABSENT,
                    MISSING_VALUE,
                )
            )
        for member in sorted(actual_keys - expected_keys):
            output.append(
                Difference(
                    _path(path, member),
                    ABSENT,
                    actual[member],
                    EXTRA_VALUE,
                )
            )
        for member in sorted(expected_keys & actual_keys):
            _collect_differences(
                expected[member],
                actual[member],
                _path(path, member),
                output,
            )
        return

    if isinstance(expected, list) and isinstance(actual, list):
        common_length = min(len(expected), len(actual))
        for index in range(common_length):
            _collect_differences(
                expected[index],
                actual[index],
                f"{path}[{index}]",
                output,
            )
        for index in range(common_length, len(expected)):
            output.append(
                Difference(
                    f"{path}[{index}]",
                    expected[index],
                    ABSENT,
                    MISSING_VALUE,
                )
            )
        for index in range(common_length, len(actual)):
            output.append(
                Difference(
                    f"{path}[{index}]",
                    ABSENT,
                    actual[index],
                    EXTRA_VALUE,
                )
            )
        return

    if type(expected) is not type(actual):
        output.append(Difference(path, expected, actual, TYPE_MISMATCH))
    elif expected != actual:
        output.append(Difference(path, expected, actual, VALUE_MISMATCH))


def find_differences(source_record: Any, restored_record: Any) -> list[Difference]:
    """Возвращает полный список видимых различий без вычисления хешей."""

    expected = _source_record_for_comparison(source_record)
    differences: list[Difference] = []
    _collect_differences(expected, restored_record, "", differences)
    return differences


def _byte_trace(payload: Any, side: str) -> str:
    if not isinstance(payload, bytes):
        _error(
            "E_INVALID_CANONICAL_BYTES",
            f"{side} путь не вернул канонические bytes",
        )
    return sha256(payload).hexdigest()


def compare_records(
    source_record: Any,
    restored_record: Any,
    *,
    source_bytes: bytes | None = None,
    restored_bytes: bytes | None = None,
) -> ComparisonResult:
    """Сравнивает записи видимо и добавляет SHA-256 как компактный след.

    Явные ``source_bytes`` и ``restored_bytes`` полезны при проверке уже
    сохранённых артефактов. Если они не переданы, байты получаются прямой
    функцией исключительно на финальном этапе вычисления следа.
    """

    differences = find_differences(source_record, restored_record)
    if source_bytes is None:
        source_bytes = canonical_record_bytes(source_record)
    if restored_bytes is None:
        restored_bytes = canonical_record_bytes(restored_record)
    return ComparisonResult(
        differences=differences,
        source_sha256=_byte_trace(source_bytes, "исходный"),
        restored_sha256=_byte_trace(restored_bytes, "обратный"),
    )


def _shown(value: Any) -> str:
    if value is ABSENT:
        return "<отсутствует>"
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return repr(value)


def format_differences(differences: Sequence[Difference]) -> str:
    """Показывает список различий понятными оператору русскими строками."""

    if not differences:
        return "Видимых различий нет."
    labels = {
        VALUE_MISMATCH: "значение отличается",
        MISSING_VALUE: "значение отсутствует",
        EXTRA_VALUE: "лишнее значение",
        TYPE_MISMATCH: "другой тип",
    }
    lines: list[str] = []
    for difference in differences:
        label = labels.get(difference.kind, difference.kind)
        lines.append(
            f"{difference.path}: {label}; ожидалось "
            f"{_shown(difference.expected)}, получено {_shown(difference.actual)}"
        )
    return "\n".join(lines)


def format_comparison(result: ComparisonResult) -> str:
    """Формирует полный операторский отчёт, включая статус хеш-следов."""

    lines = [
        f"SHA-256 исходных байтов: {result.source_sha256}",
        f"SHA-256 обратных байтов: {result.restored_sha256}",
    ]
    if result.hash_conflict:
        lines.append(
            "ПРОТИВОРЕЧИЕ: SHA-256 совпадают, но видимое сравнение нашло различия."
        )
    elif not result.hashes_match:
        lines.append("SHA-256-следы различаются; решение задаёт видимое сравнение.")
    lines.append(format_differences(result.differences))
    return "\n".join(lines)


def verify_round_trip(record: Any) -> ComparisonResult:
    """Проводит запись через прямой путь, разбор и видимое сравнение."""

    source_bytes = canonical_record_bytes(record)
    restored_record = parse_canonical_record(source_bytes)
    restored_bytes = canonical_record_bytes(restored_record)
    return compare_records(
        record,
        restored_record,
        source_bytes=source_bytes,
        restored_bytes=restored_bytes,
    )


# Ясные синонимы для употребления в прикладном коде без изменения контракта.
deserialize_canonical_record = parse_canonical_record
round_trip_check = verify_round_trip


__all__ = [
    "ABSENT",
    "EXTRA_VALUE",
    "MISSING_VALUE",
    "TYPE_MISMATCH",
    "VALUE_MISMATCH",
    "ComparisonResult",
    "Difference",
    "ReverseError",
    "compare_records",
    "deserialize_canonical_record",
    "find_differences",
    "format_comparison",
    "format_differences",
    "parse_canonical_record",
    "round_trip_check",
    "verify_round_trip",
]
