"""Канонический манифест запуска и его подпись Ed25519.

Содержательная часть манифеста состоит из версии схемы, упорядоченных входов,
упорядоченных записей, версий, хешей и решений. Порядок элементов массивов
всегда сохраняется. Каждая запись обязана нести явную позицию от 1 до N.

Подписываемая область — компактный канонический UTF-8 JSON всей
содержательной части и объекта ``signature`` с полями ``algorithm`` и
``public_key``. Из неё исключается только ``signature.value``: это результат
подписи, поэтому он не может входить в собственные входные байты. Таким
образом, алгоритм, открытый ключ, все записи, их порядок и позиции связаны
одной подписью. Полный канонический документ дополнительно содержит
``signature.value`` в Base64.

Внешней метки времени RFC 3161 и отдельного цепного хеша в этой схеме нет.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping, Sequence
from typing import Any, Never

# Библиотека подписей двоичная: она собрана под свою систему и в
# изделие ядра не укладывается (шаг 71). Ввоз потому мягкий: без неё
# подписание паспорта недоступно, а разбор, проверки и выгрузка работают полностью.
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ПОДПИСИ_ДОСТУПНЫ = True
except ImportError:  # pragma: no cover — проверяется установкой
    ПОДПИСИ_ДОСТУПНЫ = False
    serialization = None
    Ed25519PrivateKey = None


def _требуются_подписи() -> None:
    """Роняет отказом с внятной причиной, а не именем ошибки ввоза."""
    if not ПОДПИСИ_ДОСТУПНЫ:
        raise RuntimeError(
            "E_LIB_MISSING: библиотека подписей не установлена — "
            "подписание паспорта недоступно. Разбор, проверки и выгрузка "
            "в Excel работают без неё")


MANIFEST_SCHEMA_VERSION = "run-manifest/1"
SIGNATURE_ALGORITHM = "Ed25519"

_CONTENT_KEYS = (
    "schema_version",
    "inputs",
    "records",
    "versions",
    "hashes",
    "decisions",
)
_SIGNATURE_KEYS = ("algorithm", "public_key", "value")
_ALLOWED_SIGNATURE_ALGORITHMS = frozenset({SIGNATURE_ALGORITHM})


class ManifestError(ValueError):
    """Ошибка построения, канонизации или подписи манифеста."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _error(code: str, message: str) -> Never:
    raise ManifestError(code, message)


def _is_array(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    )


def _canonical_value(value: Any, path: str, active: set[int]) -> Any:
    """Копирует допустимое JSON-значение, сортируя только ключи объектов."""

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        _error("E_FLOAT_NOT_ALLOWED", f"float запрещён: {path}")
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
                key: _canonical_value(value[key], f"{path}.{key}", active)
                for key in sorted(value)
            }
        finally:
            active.remove(identity)
    if _is_array(value):
        identity = id(value)
        if identity in active:
            _error("E_CYCLIC_VALUE", f"циклическое значение запрещено: {path}")
        active.add(identity)
        try:
            return [
                _canonical_value(item, f"{path}[{index}]", active)
                for index, item in enumerate(value)
            ]
        finally:
            active.remove(identity)
    _error(
        "E_UNSUPPORTED_VALUE_TYPE",
        f"неподдерживаемый тип {type(value).__name__}: {path}",
    )


def _require_array(value: Any, path: str) -> Sequence[Any]:
    if not _is_array(value):
        _error("E_INVALID_FIELD_TYPE", f"{path} должно быть массивом")
    return value


def _require_object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _error("E_INVALID_FIELD_TYPE", f"{path} должно быть объектом")
    if not all(isinstance(key, str) for key in value):
        _error("E_INVALID_FIELD_TYPE", f"ключи {path} должны быть строками")
    return value


def _validate_positions(records: Sequence[Any]) -> None:
    for index, record in enumerate(records):
        path = f"manifest.records[{index}]"
        mapping = _require_object(record, path)
        if "position" not in mapping:
            _error(
                "E_INVALID_POSITIONS",
                f"у записи отсутствует обязательная позиция: {path}.position",
            )
        position = mapping["position"]
        if isinstance(position, bool) or not isinstance(position, int):
            _error(
                "E_INVALID_POSITIONS",
                f"позиция должна быть целым числом: {path}.position",
            )
        expected = index + 1
        if position != expected:
            _error(
                "E_INVALID_POSITIONS",
                f"ожидалась позиция {expected}, получена {position}: {path}",
            )


def _decode_base64(value: Any, path: str, size: int) -> bytes:
    if not isinstance(value, str):
        _error("E_INVALID_FIELD_TYPE", f"{path} должно быть строкой Base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ManifestError(
            "E_INVALID_BASE64", f"некорректное значение Base64: {path}"
        ) from exc
    if len(decoded) != size or base64.b64encode(decoded).decode("ascii") != value:
        _error(
            "E_INVALID_BASE64",
            f"{path} должно содержать канонические Base64-байты длиной {size}",
        )
    return decoded


def _normalise_content(manifest: Any, *, signature_allowed: bool) -> dict[str, Any]:
    mapping = _require_object(manifest, "manifest")
    required = set(_CONTENT_KEYS)
    for key in _CONTENT_KEYS:
        if key not in mapping:
            _error(
                "E_MISSING_REQUIRED_FIELD",
                f"отсутствует обязательное поле manifest.{key}",
            )
    allowed = required | ({"signature"} if signature_allowed else set())
    unknown = sorted(set(mapping).difference(allowed))
    if unknown:
        _error(
            "E_UNKNOWN_FIELD",
            "неизвестные поля манифеста: " + ", ".join(unknown),
        )

    schema_version = mapping["schema_version"]
    if not isinstance(schema_version, str):
        _error(
            "E_INVALID_FIELD_TYPE", "manifest.schema_version должно быть строкой"
        )
    if schema_version != MANIFEST_SCHEMA_VERSION:
        _error(
            "E_UNKNOWN_SCHEMA_VERSION",
            f"неизвестная версия схемы манифеста: {schema_version!r}",
        )

    inputs = _require_array(mapping["inputs"], "manifest.inputs")
    records = _require_array(mapping["records"], "manifest.records")
    _require_object(mapping["versions"], "manifest.versions")
    _require_object(mapping["hashes"], "manifest.hashes")
    decisions = _require_array(mapping["decisions"], "manifest.decisions")
    _validate_positions(records)

    active: set[int] = set()
    return {
        "schema_version": schema_version,
        "inputs": _canonical_value(inputs, "manifest.inputs", active),
        "records": _canonical_value(records, "manifest.records", active),
        "versions": _canonical_value(
            mapping["versions"], "manifest.versions", active
        ),
        "hashes": _canonical_value(mapping["hashes"], "manifest.hashes", active),
        "decisions": _canonical_value(decisions, "manifest.decisions", active),
    }


def _normalise_signature(value: Any) -> dict[str, str]:
    signature = _require_object(value, "manifest.signature")
    for key in _SIGNATURE_KEYS:
        if key not in signature:
            _error(
                "E_MISSING_REQUIRED_FIELD",
                f"отсутствует обязательное поле manifest.signature.{key}",
            )
    unknown = sorted(set(signature).difference(_SIGNATURE_KEYS))
    if unknown:
        _error(
            "E_UNKNOWN_FIELD",
            "неизвестные поля подписи: " + ", ".join(unknown),
        )

    algorithm = signature["algorithm"]
    if not isinstance(algorithm, str):
        _error(
            "E_INVALID_FIELD_TYPE", "manifest.signature.algorithm должно быть строкой"
        )
    if algorithm not in _ALLOWED_SIGNATURE_ALGORITHMS:
        _error(
            "E_UNKNOWN_SIGNATURE_ALGORITHM",
            f"неизвестный алгоритм подписи: {algorithm!r}",
        )
    public_key = signature["public_key"]
    value_text = signature["value"]
    _decode_base64(public_key, "manifest.signature.public_key", 32)
    _decode_base64(value_text, "manifest.signature.value", 64)
    return {
        "algorithm": algorithm,
        "public_key": public_key,
        "value": value_text,
    }


def _json_bytes(value: Any) -> bytes:
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


def _signing_bytes(content: Mapping[str, Any], signature: Mapping[str, str]) -> bytes:
    signed_document = dict(content)
    signed_document["signature"] = {
        "algorithm": signature["algorithm"],
        "public_key": signature["public_key"],
    }
    return _json_bytes(signed_document)


def build_manifest(
    inputs: Sequence[Any],
    records: Sequence[Any],
    versions: Mapping[str, Any],
    hashes: Mapping[str, Any],
    decisions: Sequence[Any],
) -> dict[str, Any]:
    """Строит неподписанную содержательную часть ``run-manifest/1``.

    Функция не сортирует массивы и не перенумеровывает записи. Позиции должны
    быть заранее заданы вызывающим как 1, 2, ..., N.
    """

    candidate = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "inputs": inputs,
        "records": records,
        "versions": versions,
        "hashes": hashes,
        "decisions": decisions,
    }
    return _normalise_content(candidate, signature_allowed=False)


def sign_manifest(
    manifest: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    algorithm: str = SIGNATURE_ALGORITHM,
) -> dict[str, Any]:
    """Возвращает новую копию манифеста с детерминированной подписью Ed25519."""

    if not isinstance(algorithm, str):
        _error("E_INVALID_FIELD_TYPE", "алгоритм подписи должен быть строкой")
    if algorithm not in _ALLOWED_SIGNATURE_ALGORITHMS:
        _error(
            "E_UNKNOWN_SIGNATURE_ALGORITHM",
            f"неизвестный алгоритм подписи: {algorithm!r}",
        )
    _требуются_подписи()
    if not isinstance(private_key, Ed25519PrivateKey):
        _error(
            "E_INVALID_PRIVATE_KEY",
            "для Ed25519 требуется объект Ed25519PrivateKey",
        )
    if isinstance(manifest, Mapping) and "signature" in manifest:
        _error("E_ALREADY_SIGNED", "манифест уже содержит подпись")

    content = _normalise_content(manifest, signature_allowed=False)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature_meta = {
        "algorithm": algorithm,
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
    }
    signature_value = private_key.sign(_signing_bytes(content, signature_meta))

    signed = dict(content)
    signed["signature"] = {
        **signature_meta,
        "value": base64.b64encode(signature_value).decode("ascii"),
    }
    return signed


def canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """Возвращает полный канонический UTF-8 JSON без перевода строки."""

    has_signature = isinstance(manifest, Mapping) and "signature" in manifest
    content = _normalise_content(manifest, signature_allowed=has_signature)
    if not has_signature:
        return _json_bytes(content)
    signature = _normalise_signature(manifest["signature"])
    complete = dict(content)
    complete["signature"] = signature
    return _json_bytes(complete)


__all__ = [
    "MANIFEST_SCHEMA_VERSION",
    "SIGNATURE_ALGORITHM",
    "ManifestError",
    "build_manifest",
    "canonical_manifest_bytes",
    "sign_manifest",
]
