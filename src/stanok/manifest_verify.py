"""Независимая проверка подписанного манифеста ``run-manifest/1``.

Этот модуль намеренно не использует код построения манифеста. Он повторно
объявляет допустимую структуру документа и самостоятельно получает байты для
проверки: компактный UTF-8 JSON полей ``schema_version``, ``inputs``,
``records``, ``versions``, ``hashes``, ``decisions`` и объекта ``signature``
только с ``algorithm`` и ``public_key``. Поле ``signature.value`` не входит в
проверяемые байты, поскольку содержит саму подпись.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from collections.abc import Mapping, Sequence
from typing import Any, Never

# Библиотека подписей двоичная: она собрана под свою систему и в
# изделие ядра не укладывается (шаг 71). Ввоз потому мягкий: без неё
# проверка подписи недоступно, а разбор, проверки и выгрузка работают полностью.
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    ПОДПИСИ_ДОСТУПНЫ = True
except ImportError:  # pragma: no cover — проверяется установкой
    ПОДПИСИ_ДОСТУПНЫ = False
    InvalidSignature = None
    serialization = None
    Ed25519PublicKey = None


def _требуются_подписи() -> None:
    """Роняет отказом с внятной причиной, а не именем ошибки ввоза."""
    if not ПОДПИСИ_ДОСТУПНЫ:
        raise RuntimeError(
            "E_LIB_MISSING: библиотека подписей не установлена — "
            "проверка подписи недоступно. Разбор, проверки и выгрузка "
            "в Excel работают без неё")


MANIFEST_SCHEMA_VERSION = "run-manifest/1"
SIGNATURE_ALGORITHM = "Ed25519"

_BODY_FIELDS = (
    "schema_version",
    "inputs",
    "records",
    "versions",
    "hashes",
    "decisions",
)
_PERMITTED_ALGORITHMS = frozenset({SIGNATURE_ALGORITHM})


class ManifestError(ValueError):
    """Ошибка структуры, каноничности или подписи манифеста."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _reject(code: str, message: str) -> Never:
    raise ManifestError(code, message)


def _array(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    )


def _ordered_json(value: Any, location: str, visiting: set[int]) -> Any:
    """Строит проверяющее представление, не меняя порядок массивов."""

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        _reject("E_FLOAT_NOT_ALLOWED", f"float запрещён: {location}")
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in visiting:
            _reject("E_CYCLIC_VALUE", f"циклическое значение запрещено: {location}")
        if any(not isinstance(key, str) for key in value):
            _reject(
                "E_INVALID_FIELD_TYPE",
                f"ключи объекта должны быть строками: {location}",
            )
        visiting.add(marker)
        try:
            return {
                key: _ordered_json(value[key], f"{location}.{key}", visiting)
                for key in sorted(value)
            }
        finally:
            visiting.remove(marker)
    if _array(value):
        marker = id(value)
        if marker in visiting:
            _reject("E_CYCLIC_VALUE", f"циклическое значение запрещено: {location}")
        visiting.add(marker)
        try:
            return [
                _ordered_json(item, f"{location}[{index}]", visiting)
                for index, item in enumerate(value)
            ]
        finally:
            visiting.remove(marker)
    _reject(
        "E_UNSUPPORTED_VALUE_TYPE",
        f"неподдерживаемый тип {type(value).__name__}: {location}",
    )


def _object(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _reject("E_INVALID_FIELD_TYPE", f"{location} должно быть объектом")
    if any(not isinstance(key, str) for key in value):
        _reject("E_INVALID_FIELD_TYPE", f"ключи {location} должны быть строками")
    return value


def _sequence(value: Any, location: str) -> Sequence[Any]:
    if not _array(value):
        _reject("E_INVALID_FIELD_TYPE", f"{location} должно быть массивом")
    return value


def _check_record_positions(records: Sequence[Any]) -> None:
    for offset, item in enumerate(records):
        location = f"manifest.records[{offset}]"
        record = _object(item, location)
        if "position" not in record:
            _reject(
                "E_INVALID_POSITIONS",
                f"у записи отсутствует обязательная позиция: {location}.position",
            )
        position = record["position"]
        if isinstance(position, bool) or not isinstance(position, int):
            _reject(
                "E_INVALID_POSITIONS",
                f"позиция должна быть целым числом: {location}.position",
            )
        expected = offset + 1
        if position != expected:
            _reject(
                "E_INVALID_POSITIONS",
                f"ожидалась позиция {expected}, получена {position}: {location}",
            )


def _base64_bytes(value: Any, location: str, length: int) -> bytes:
    if not isinstance(value, str):
        _reject("E_INVALID_FIELD_TYPE", f"{location} должно быть строкой Base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ManifestError(
            "E_INVALID_BASE64", f"некорректное значение Base64: {location}"
        ) from exc
    canonical_text = base64.b64encode(raw).decode("ascii")
    if len(raw) != length or not hmac.compare_digest(canonical_text, value):
        _reject(
            "E_INVALID_BASE64",
            f"{location} должно содержать канонические Base64-байты длиной {length}",
        )
    return raw


def _manifest_parts(document: Any) -> tuple[dict[str, Any], dict[str, str], bytes, bytes]:
    root = _object(document, "manifest")
    required = set(_BODY_FIELDS) | {"signature"}
    absent = [name for name in (*_BODY_FIELDS, "signature") if name not in root]
    if absent:
        _reject(
            "E_MISSING_REQUIRED_FIELD",
            f"отсутствует обязательное поле manifest.{absent[0]}",
        )
    extra = sorted(set(root).difference(required))
    if extra:
        _reject("E_UNKNOWN_FIELD", "неизвестные поля манифеста: " + ", ".join(extra))

    schema = root["schema_version"]
    if not isinstance(schema, str):
        _reject("E_INVALID_FIELD_TYPE", "manifest.schema_version должно быть строкой")
    if schema != MANIFEST_SCHEMA_VERSION:
        _reject(
            "E_UNKNOWN_SCHEMA_VERSION",
            f"неизвестная версия схемы манифеста: {schema!r}",
        )

    inputs = _sequence(root["inputs"], "manifest.inputs")
    records = _sequence(root["records"], "manifest.records")
    _object(root["versions"], "manifest.versions")
    _object(root["hashes"], "manifest.hashes")
    decisions = _sequence(root["decisions"], "manifest.decisions")
    _check_record_positions(records)

    signature_source = _object(root["signature"], "manifest.signature")
    signature_fields = {"algorithm", "public_key", "value"}
    absent_signature = [
        name for name in ("algorithm", "public_key", "value")
        if name not in signature_source
    ]
    if absent_signature:
        _reject(
            "E_MISSING_REQUIRED_FIELD",
            "отсутствует обязательное поле "
            f"manifest.signature.{absent_signature[0]}",
        )
    extra_signature = sorted(set(signature_source).difference(signature_fields))
    if extra_signature:
        _reject(
            "E_UNKNOWN_FIELD",
            "неизвестные поля подписи: " + ", ".join(extra_signature),
        )

    algorithm = signature_source["algorithm"]
    if not isinstance(algorithm, str):
        _reject(
            "E_INVALID_FIELD_TYPE", "manifest.signature.algorithm должно быть строкой"
        )
    if algorithm not in _PERMITTED_ALGORITHMS:
        _reject(
            "E_UNKNOWN_SIGNATURE_ALGORITHM",
            f"неизвестный алгоритм подписи: {algorithm!r}",
        )
    public_text = signature_source["public_key"]
    value_text = signature_source["value"]
    public_raw = _base64_bytes(public_text, "manifest.signature.public_key", 32)
    signature_raw = _base64_bytes(value_text, "manifest.signature.value", 64)

    visiting: set[int] = set()
    body = {
        "schema_version": schema,
        "inputs": _ordered_json(inputs, "manifest.inputs", visiting),
        "records": _ordered_json(records, "manifest.records", visiting),
        "versions": _ordered_json(root["versions"], "manifest.versions", visiting),
        "hashes": _ordered_json(root["hashes"], "manifest.hashes", visiting),
        "decisions": _ordered_json(decisions, "manifest.decisions", visiting),
    }
    signature = {
        "algorithm": algorithm,
        "public_key": public_text,
        "value": value_text,
    }
    return body, signature, public_raw, signature_raw


def _encode_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ManifestError(
            "E_JSON_SERIALIZATION",
            "манифест нельзя представить каноническим UTF-8 JSON",
        ) from exc


class _DuplicateJsonKey(ValueError):
    pass


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _parse_presented(value: Any) -> tuple[Any, bytes | None]:
    if isinstance(value, Mapping):
        return value, None
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ManifestError(
                "E_INVALID_JSON", "манифест должен быть корректным UTF-8 JSON"
            ) from exc
    elif isinstance(value, (bytes, bytearray, memoryview)):
        encoded = bytes(value)
    else:
        _reject(
            "E_INVALID_MANIFEST_TYPE",
            "манифест должен быть объектом, строкой JSON или байтами JSON",
        )

    try:
        text = encoded.decode("utf-8")
        parsed = json.loads(text, object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        raise ManifestError(
            "E_INVALID_JSON", "манифест должен быть корректным UTF-8 JSON"
        ) from exc
    except _DuplicateJsonKey as exc:
        raise ManifestError(
            "E_DUPLICATE_JSON_KEY", f"повторяющийся ключ JSON: {exc.args[0]!r}"
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ManifestError("E_INVALID_JSON", "некорректный JSON манифеста") from exc
    return parsed, encoded


def _trusted_public_bytes(value: Any) -> bytes:
    if isinstance(value, Ed25519PublicKey):
        return value.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    if isinstance(value, str):
        return _base64_bytes(value, "expected_public_key", 32)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) != 32:
            _reject(
                "E_INVALID_PUBLIC_KEY",
                "ожидаемый открытый ключ Ed25519 должен иметь длину 32 байта",
            )
        return raw
    _reject(
        "E_INVALID_PUBLIC_KEY",
        "ожидаемый ключ должен быть Ed25519PublicKey, 32 байтами или Base64",
    )


def verify_manifest(
    manifest: Mapping[str, Any] | str | bytes | bytearray | memoryview,
    expected_public_key: Ed25519PublicKey | str | bytes | bytearray | memoryview | None = None,
) -> bool:
    """Проверяет структуру, каноничность, позиции и подпись манифеста.

    Для объекта проверяется его каноническое смысловое представление. Если
    переданы JSON-байты или строка, их форма тоже обязана в точности совпасть с
    канонической. ``expected_public_key`` привязывает проверку к доверенному
    ключу извне и защищает также от совместной замены ключа и подписи.
    """

    document, presented_bytes = _parse_presented(manifest)
    body, signature, embedded_public, signature_value = _manifest_parts(document)

    complete = dict(body)
    complete["signature"] = signature
    canonical_complete = _encode_json(complete)
    if presented_bytes is not None and not hmac.compare_digest(
        canonical_complete, presented_bytes
    ):
        _reject(
            "E_NON_CANONICAL_MANIFEST",
            "представленный JSON манифеста не является каноническим",
        )

    verification_public = embedded_public
    if expected_public_key is not None:
        trusted_public = _trusted_public_bytes(expected_public_key)
        if not hmac.compare_digest(trusted_public, embedded_public):
            _reject(
                "E_PUBLIC_KEY_MISMATCH",
                "открытый ключ манифеста не совпадает с доверенным ключом",
            )
        verification_public = trusted_public

    signed_document = dict(body)
    signed_document["signature"] = {
        "algorithm": signature["algorithm"],
        "public_key": signature["public_key"],
    }
    verified_bytes = _encode_json(signed_document)
    try:
        _требуются_подписи()
        public_key = Ed25519PublicKey.from_public_bytes(verification_public)
        public_key.verify(signature_value, verified_bytes)
    except (InvalidSignature, ValueError) as exc:
        raise ManifestError(
            "E_INVALID_SIGNATURE", "подпись манифеста недействительна"
        ) from exc
    return True


__all__ = [
    "MANIFEST_SCHEMA_VERSION",
    "SIGNATURE_ALGORITHM",
    "ManifestError",
    "verify_manifest",
]
