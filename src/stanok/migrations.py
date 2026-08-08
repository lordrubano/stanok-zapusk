"""Версии схем, обратное чтение и проверяемые миграции артефактов.

Слой намеренно расположен над существующими модулями. Он не меняет их
контракты: ``record/1`` и ``run-manifest/1`` проверяются их штатными
канонизаторами, а отсутствие ``schema_version`` в строках журнала означает
``journal/1``.

``journal/2`` добавляет ``schema_version`` в каждую строку. Поле входит в
канонические байты записи, поэтому при переходе цепь SHA-256 строится заново.
Каждый выполненный шаг возвращает отдельную запись происхождения со старой и
новой вершинами. История таких записей переносится через последующие миграции
и откаты.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
from collections import Counter, deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, ClassVar, Never

from . import canonical as canonical_module
from . import journal as journal_module
from . import manifest as manifest_module
from . import manifest_verify


RECORD_SCHEMA_VERSION = "record/1"
MANIFEST_SCHEMA_VERSION = "run-manifest/1"
LEGACY_JOURNAL_SCHEMA_VERSION = "journal/1"
JOURNAL_SCHEMA_VERSION = "journal/2"
MIGRATION_RECORD_SCHEMA_VERSION = "migration-record/1"

_RECORD = "record"
_MANIFEST = "run-manifest"
_JOURNAL = "journal"
_TOOLING = "tooling"

TOOLING_SCHEMA_VERSION = "tooling/2"
LEGACY_TOOLING_SCHEMA_VERSION = "tooling/1"

SCHEMA_VERSIONS = MappingProxyType(
    {
        _RECORD: (RECORD_SCHEMA_VERSION,),
        _MANIFEST: (MANIFEST_SCHEMA_VERSION,),
        _JOURNAL: (
            LEGACY_JOURNAL_SCHEMA_VERSION,
            JOURNAL_SCHEMA_VERSION,
        ),
        _TOOLING: (
            LEGACY_TOOLING_SCHEMA_VERSION,
            TOOLING_SCHEMA_VERSION,
        ),
    }
)
"""Поддерживаемые версии каждого семейства в хронологическом порядке."""

CURRENT_VERSIONS = MappingProxyType(
    {
        artifact_type: versions[-1]
        for artifact_type, versions in SCHEMA_VERSIONS.items()
    }
)
"""Текущие версии; семейства обновляются независимо друг от друга."""

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
_JOURNAL_1_FIELDS = ("sequence", "previous_hash", *_PAYLOAD_FIELDS, "hash")
_JOURNAL_2_FIELDS = (
    "schema_version",
    "sequence",
    "previous_hash",
    *_PAYLOAD_FIELDS,
    "hash",
)


class MigrationError(ValueError):
    """Ошибка чтения или миграции с машинным кодом."""

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


def _error(
    code: str,
    message: str,
    *,
    record_number: int | None = None,
) -> Never:
    raise MigrationError(code, message, record_number=record_number)


@dataclass(frozen=True)
class VersionedArtifact:
    """Прочитанный и проверенный артефакт без неявной миграции."""

    artifact_type: str
    schema_version: str
    data: Any

    @property
    def version(self) -> str:
        return self.schema_version


@dataclass(frozen=True)
class MigrationRecord(Mapping[str, Any]):
    """Проверяемая запись происхождения одного шага миграции."""

    artifact_type: str
    migration_version: str
    source_version: str
    target_version: str
    old_head: str | None
    new_head: str | None
    record_count_before: int
    record_count_after: int
    schema_version: str = MIGRATION_RECORD_SCHEMA_VERSION

    _FIELDS: ClassVar[tuple[str, ...]] = (
        "schema_version",
        "artifact_type",
        "migration_version",
        "source_version",
        "target_version",
        "old_head",
        "new_head",
        "record_count_before",
        "record_count_after",
    )

    def __getitem__(self, key: str) -> Any:
        if key not in self._FIELDS:
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self) -> Iterator[str]:
        return iter(self._FIELDS)

    def __len__(self) -> int:
        return len(self._FIELDS)

    def as_dict(self) -> dict[str, Any]:
        """Возвращает JSON-совместимую копию записи."""

        return {field: getattr(self, field) for field in self._FIELDS}


@dataclass(frozen=True)
class MigrationResult:
    """Артефакт вместе с неутраченной историей выполненных переходов."""

    artifact_type: str
    source_version: str
    target_version: str
    artifact: Any
    migration_records: tuple[MigrationRecord, ...] = ()

    @property
    def data(self) -> Any:
        return self.artifact

    @property
    def schema_version(self) -> str:
        return self.target_version

    @property
    def version(self) -> str:
        return self.target_version

    @property
    def migration_record(self) -> MigrationRecord | None:
        """Последняя запись перехода или ``None`` для идемпотентного чтения."""

        return self.migration_records[-1] if self.migration_records else None


MigrationTransform = Callable[[Any], Any]


@dataclass(frozen=True)
class MigrationStep:
    """Один соседний переход в реестре схем."""

    artifact_type: str
    source_version: str
    target_version: str
    migration_version: str
    transform: MigrationTransform


class MigrationRegistry:
    """Упорядоченный реестр шагов с детерминированным поиском маршрута."""

    def __init__(self, steps: Sequence[MigrationStep] = ()) -> None:
        ordered: list[MigrationStep] = []
        directions: set[tuple[str, str, str]] = set()
        for step in steps:
            if not isinstance(step, MigrationStep):
                _error(
                    "E_INVALID_MIGRATION_STEP",
                    "реестр может содержать только объекты MigrationStep",
                )
            artifact_type = _normalise_artifact_type(step.artifact_type)
            versions = SCHEMA_VERSIONS[artifact_type]
            if (
                step.source_version not in versions
                or step.target_version not in versions
            ):
                _error(
                    "E_UNKNOWN_SCHEMA_VERSION",
                    "шаг ссылается на неподдерживаемую версию схемы",
                )
            source_index = versions.index(step.source_version)
            target_index = versions.index(step.target_version)
            if abs(source_index - target_index) != 1:
                _error(
                    "E_NON_ADJACENT_MIGRATION",
                    "переход разрешён только между соседними версиями схемы",
                )
            if not step.migration_version or not isinstance(
                step.migration_version, str
            ):
                _error(
                    "E_INVALID_MIGRATION_STEP",
                    "версия миграции должна быть непустой строкой",
                )
            if not callable(step.transform):
                _error(
                    "E_INVALID_MIGRATION_STEP",
                    "преобразователь шага должен быть вызываемым объектом",
                )
            direction = (
                artifact_type,
                step.source_version,
                step.target_version,
            )
            if direction in directions:
                _error(
                    "E_DUPLICATE_MIGRATION_STEP",
                    "направление миграции зарегистрировано повторно",
                )
            directions.add(direction)
            if artifact_type != step.artifact_type:
                step = MigrationStep(
                    artifact_type,
                    step.source_version,
                    step.target_version,
                    step.migration_version,
                    step.transform,
                )
            ordered.append(step)
        self._steps = tuple(ordered)

    @property
    def steps(self) -> tuple[MigrationStep, ...]:
        return self._steps

    def route(
        self,
        artifact_type: str,
        source_version: str,
        target_version: str,
    ) -> tuple[MigrationStep, ...]:
        """Возвращает маршрут из последовательных соседних шагов."""

        artifact_type = _normalise_artifact_type(artifact_type)
        versions = SCHEMA_VERSIONS[artifact_type]
        _require_known_version(artifact_type, source_version)
        _require_known_version(artifact_type, target_version)
        if source_version == target_version:
            return ()

        queue: deque[tuple[str, tuple[MigrationStep, ...]]] = deque(
            [(source_version, ())]
        )
        visited = {source_version}
        while queue:
            version, path = queue.popleft()
            for step in self._steps:
                if (
                    step.artifact_type != artifact_type
                    or step.source_version != version
                ):
                    continue
                next_version = step.target_version
                next_path = (*path, step)
                if next_version == target_version:
                    return next_path
                if next_version not in visited:
                    visited.add(next_version)
                    queue.append((next_version, next_path))

        _error(
            "E_MIGRATION_PATH_NOT_FOUND",
            "не найден последовательный путь миграции "
            f"{source_version!r} → {target_version!r}",
        )


class _DuplicateKeyError(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(key)


def _normalise_artifact_type(artifact_type: str) -> str:
    if not isinstance(artifact_type, str):
        _error("E_INVALID_ARTIFACT_TYPE", "вид артефакта должен быть строкой")
    aliases = {
        "record": _RECORD,
        "manifest": _MANIFEST,
        "run-manifest": _MANIFEST,
        "journal": _JOURNAL,
        "tooling": _TOOLING,
        "оснастка": _TOOLING,
    }
    try:
        return aliases[artifact_type]
    except KeyError:
        _error(
            "E_UNKNOWN_ARTIFACT_TYPE",
            f"неизвестный вид артефакта: {artifact_type!r}",
        )


def _require_known_version(artifact_type: str, version: Any) -> str:
    if not isinstance(version, str):
        _error("E_INVALID_SCHEMA_VERSION", "версия схемы должна быть строкой")
    if version not in SCHEMA_VERSIONS[artifact_type]:
        _error(
            "E_UNKNOWN_SCHEMA_VERSION",
            f"неизвестная или будущая версия схемы: {version!r}",
        )
    return version


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"недопустимая JSON-константа {value}")


def _decode_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationError(
            "E_INVALID_UTF8", f"{label} не является корректным UTF-8"
        ) from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError as exc:
        raise MigrationError(
            "E_DUPLICATE_KEY", f"повторяющийся ключ JSON: {exc.key}"
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise MigrationError(
            "E_INVALID_JSON", f"{label} не является корректным JSON"
        ) from exc


def _read_file(path: os.PathLike[str] | str, label: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise MigrationError(
            "E_IO", f"не удалось прочитать {label}: {Path(path)}"
        ) from exc


def _json_artifact_value(source: Any, label: str) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        value = copy.deepcopy(source)
    elif isinstance(source, os.PathLike):
        value = _decode_json(_read_file(source, label), label)
    elif isinstance(source, bytes):
        value = _decode_json(source, label)
    elif isinstance(source, str):
        text = source.lstrip()
        raw = (
            source.encode("utf-8")
            if text.startswith("{")
            else _read_file(source, label)
        )
        value = _decode_json(raw, label)
    else:
        _error(
            "E_INVALID_ARTIFACT",
            f"{label} должен быть объектом, JSON или локальным файлом",
        )
    if not isinstance(value, Mapping):
        _error("E_INVALID_ARTIFACT", f"{label} должен быть JSON-объектом")
    if any(not isinstance(key, str) for key in value):
        _error(
            "E_INVALID_FIELD_TYPE", f"ключи объекта {label} должны быть строками"
        )
    return value


def _declared_version(
    artifact_type: str,
    value: Mapping[str, Any],
    label: str,
) -> str:
    if "schema_version" not in value:
        _error(
            "E_MISSING_SCHEMA_VERSION",
            f"в {label} отсутствует поле schema_version",
        )
    return _require_known_version(artifact_type, value["schema_version"])


def _component_error(error: Exception, label: str) -> Never:
    code = getattr(error, "code", "E_INVALID_ARTIFACT")
    record_number = getattr(error, "record_number", None)
    _error(
        code,
        f"{label} не прошёл штатную проверку: {error}",
        record_number=record_number,
    )


def _read_record(source: Any) -> VersionedArtifact:
    value = _json_artifact_value(source, "запись")
    version = _declared_version(_RECORD, value, "записи")
    try:
        canonical = canonical_module.canonical_record_bytes(value)
    except canonical_module.CanonicalError as exc:
        _component_error(exc, "запись")
    return VersionedArtifact(_RECORD, version, _decode_json(canonical, "запись"))


def _read_manifest(source: Any) -> VersionedArtifact:
    value = _json_artifact_value(source, "манифест")
    version = _declared_version(_MANIFEST, value, "манифесте")
    try:
        canonical = manifest_module.canonical_manifest_bytes(value)
        if "signature" in value:
            manifest_verify.verify_manifest(canonical)
    except (manifest_module.ManifestError, manifest_verify.ManifestError) as exc:
        _component_error(exc, "манифест")
    return VersionedArtifact(
        _MANIFEST,
        version,
        _decode_json(canonical, "манифест"),
    )


def _journal_entries_from_bytes(raw: bytes) -> list[dict[str, Any]]:
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        _error(
            "E_TRUNCATED_RECORD",
            "последняя строка журнала не завершена переводом строки",
        )
    entries: list[dict[str, Any]] = []
    for record_number, raw_line in enumerate(raw.splitlines(keepends=True), start=1):
        value = _decode_json(raw_line[:-1], f"строка журнала {record_number}")
        if not isinstance(value, Mapping):
            _error(
                "E_INVALID_ARTIFACT",
                "строка журнала должна быть JSON-объектом",
                record_number=record_number,
            )
        entries.append(dict(value))
    return entries


def _journal_entries(source: Any) -> list[dict[str, Any]]:
    if isinstance(source, os.PathLike):
        return _journal_entries_from_bytes(_read_file(source, "журнал"))
    if isinstance(source, bytes):
        return _journal_entries_from_bytes(source)
    if isinstance(source, str):
        text = source.lstrip()
        raw = (
            source.encode("utf-8")
            if text.startswith("{") or "\n" in source or "\r" in source
            else _read_file(source, "журнал")
        )
        return _journal_entries_from_bytes(raw)
    if isinstance(source, Sequence) and not isinstance(
        source, (str, bytes, bytearray, memoryview)
    ):
        result: list[dict[str, Any]] = []
        for record_number, entry in enumerate(source, start=1):
            if not isinstance(entry, Mapping):
                _error(
                    "E_INVALID_ARTIFACT",
                    "запись журнала должна быть объектом",
                    record_number=record_number,
                )
            result.append(copy.deepcopy(dict(entry)))
        return result
    _error(
        "E_INVALID_ARTIFACT",
        "журнал должен быть JSON Lines, локальным файлом или массивом записей",
    )


def _detect_journal_version(entries: Sequence[Mapping[str, Any]]) -> str:
    present = ["schema_version" in entry for entry in entries]
    if not any(present):
        return LEGACY_JOURNAL_SCHEMA_VERSION
    if not all(present):
        _error(
            "E_MIXED_SCHEMA_VERSIONS",
            "в одном журнале смешаны записи с версией схемы и без неё",
        )
    declared = [entry["schema_version"] for entry in entries]
    if any(not isinstance(version, str) for version in declared):
        _error(
            "E_INVALID_SCHEMA_VERSION",
            "версия схемы записи журнала должна быть строкой",
        )
    versions = set(declared)
    if len(versions) != 1:
        _error(
            "E_MIXED_SCHEMA_VERSIONS",
            "в одном журнале смешаны разные версии схемы",
        )
    version = next(iter(versions))
    if version == LEGACY_JOURNAL_SCHEMA_VERSION:
        _error(
            "E_INVALID_SCHEMA_VERSION",
            "journal/1 опознаётся только по отсутствию schema_version",
        )
    return _require_known_version(_JOURNAL, version)


def _validate_hash(
    value: Any,
    path: str,
    record_number: int | None,
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


def _journal_2_canonical_bytes(
    payload: Mapping[str, Any],
    sequence: int,
    previous_hash: str,
) -> bytes:
    """Включает версию journal/2 в область цепного хеша."""

    legacy_bytes = journal_module.canonical_record_bytes(
        payload, sequence, previous_hash
    )
    legacy_value = json.loads(legacy_bytes)
    versioned_value = {
        "schema_version": JOURNAL_SCHEMA_VERSION,
        **legacy_value,
    }
    return json.dumps(
        versioned_value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _journal_hash(
    version: str,
    payload: Mapping[str, Any],
    sequence: int,
    previous_hash: str,
) -> str:
    try:
        canonical = (
            journal_module.canonical_record_bytes(
                payload, sequence, previous_hash
            )
            if version == LEGACY_JOURNAL_SCHEMA_VERSION
            else _journal_2_canonical_bytes(payload, sequence, previous_hash)
        )
    except journal_module.JournalError as exc:
        _component_error(exc, "запись журнала")
    return hashlib.sha256(canonical).hexdigest()


def _validate_journal(
    entries: Sequence[Mapping[str, Any]],
    version: str,
) -> str:
    expected_fields = (
        _JOURNAL_1_FIELDS
        if version == LEGACY_JOURNAL_SCHEMA_VERSION
        else _JOURNAL_2_FIELDS
    )
    expected_set = set(expected_fields)
    previous_hash = journal_module.CHAIN_START
    for record_number, entry in enumerate(entries, start=1):
        if any(not isinstance(key, str) for key in entry):
            _error(
                "E_INVALID_FIELD_TYPE",
                "ключи записи журнала должны быть строками",
                record_number=record_number,
            )
        missing = [field for field in expected_fields if field not in entry]
        if missing:
            _error(
                "E_MISSING_REQUIRED_FIELD",
                f"отсутствует обязательное поле record.{missing[0]}",
                record_number=record_number,
            )
        unknown = sorted(set(entry).difference(expected_set))
        if unknown:
            _error(
                "E_UNKNOWN_FIELD",
                "неизвестные поля записи: " + ", ".join(unknown),
                record_number=record_number,
            )
        if version == JOURNAL_SCHEMA_VERSION and entry["schema_version"] != version:
            _error(
                "E_MIXED_SCHEMA_VERSIONS",
                "версия записи не совпадает с версией журнала",
                record_number=record_number,
            )

        sequence = entry["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            _error(
                "E_INVALID_FIELD_TYPE",
                "record.sequence должно быть целым числом",
                record_number=record_number,
            )
        if sequence != record_number:
            _error(
                "E_SEQUENCE_MISMATCH",
                f"ожидался номер {record_number}, получен {sequence}",
                record_number=record_number,
            )
        stored_previous = _validate_hash(
            entry["previous_hash"], "record.previous_hash", record_number
        )
        if not hmac.compare_digest(stored_previous, previous_hash):
            _error(
                "E_PREVIOUS_HASH_MISMATCH",
                "хеш предыдущей записи не совпадает с вершиной префикса",
                record_number=record_number,
            )
        payload = {field: entry[field] for field in _PAYLOAD_FIELDS}
        actual_hash = _journal_hash(
            version,
            payload,
            sequence,
            stored_previous,
        )
        stored_hash = _validate_hash(entry["hash"], "record.hash", record_number)
        if not hmac.compare_digest(stored_hash, actual_hash):
            _error(
                "E_HASH_MISMATCH",
                "собственный хеш записи не совпадает с её содержимым",
                record_number=record_number,
            )
        previous_hash = stored_hash
    return previous_hash


def _read_journal(source: Any) -> VersionedArtifact:
    entries = _journal_entries(source)
    version = _detect_journal_version(entries)
    _validate_journal(entries, version)
    return VersionedArtifact(_JOURNAL, version, entries)


def read_artifact(artifact_type: str, source: Any) -> VersionedArtifact:
    """Читает поддерживаемую версию без её автоматического обновления."""

    artifact_type = _normalise_artifact_type(artifact_type)
    if isinstance(source, MigrationResult):
        if source.artifact_type != artifact_type:
            _error(
                "E_ARTIFACT_TYPE_MISMATCH",
                "результат миграции относится к другому виду артефакта",
            )
        source = source.artifact
    elif isinstance(source, VersionedArtifact):
        if source.artifact_type != artifact_type:
            _error(
                "E_ARTIFACT_TYPE_MISMATCH",
                "прочитанный объект относится к другому виду артефакта",
            )
        claimed_version = source.schema_version
        source = source.data
        checked = read_artifact(artifact_type, source)
        if checked.schema_version != claimed_version:
            _error(
                "E_SCHEMA_VERSION_MISMATCH",
                "заявленная версия не совпадает с содержимым артефакта",
            )
        return checked

    if artifact_type == _RECORD:
        return _read_record(source)
    if artifact_type == _MANIFEST:
        return _read_manifest(source)
    if artifact_type == _TOOLING:
        return _read_tooling(source)
    return _read_journal(source)


def _read_tooling(source: Any) -> VersionedArtifact:
    """Читает объявление оснастки. Версия языка живёт в разделе «язык».

    Оснастка — не запись и не журнал: у неё нет ``schema_version``, и версия
    объявляется тем самым разделом, по которому ядро решает, читать пакет или
    отказаться (шаг 38).
    """
    value = source
    if isinstance(value, (str, bytes, os.PathLike)):
        value = _decode_json(_read_bytes(value), "объявление оснастки")
    if not isinstance(value, Mapping):
        _error("E_INVALID_ARTIFACT", "объявление оснастки должно быть объектом")
    язык = value.get("язык")
    if not isinstance(язык, str) or not язык.strip():
        _error(
            "E_MISSING_SCHEMA_VERSION",
            "в объявлении оснастки нет раздела «язык»: без него неизвестно, "
            "по какому договору читать пакет",
        )
    version = _require_known_version(_TOOLING, язык)
    return VersionedArtifact(_TOOLING, version, copy.deepcopy(dict(value)))


def _tooling_1_to_2(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Переводит объявление на второй язык. Прошлое не теряется.

    Перевод **ничего не досочиняет**: он поднимает версию и оставляет место под
    перечень обозначений валюты пустым, то есть отсутствующим. Оснастка,
    которой обозначения не нужны, работает как прежде; той, которой нужны, их
    объявляет человек — угадать обозначения за банк нельзя.
    """
    свой = copy.deepcopy(dict(artifact))
    свой["язык"] = TOOLING_SCHEMA_VERSION
    return свой


def _tooling_2_to_1(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Откат на первый язык. Непереводимое называется, а не выбрасывается.

    Если оснастка пользуется правилом второй версии, откатить её нельзя:
    выбросить правило значило бы тихо изменить смысл разбора. Отказ приходит
    здесь, а не при первом непрочитанном документе.
    """
    свой = copy.deepcopy(dict(artifact))
    нормализация = свой.get("нормализация")
    if isinstance(нормализация, Mapping) and нормализация.get(
        "обозначения_валюты"
    ):
        _error(
            "E_IRREVERSIBLE_MIGRATION",
            "откат оснастки на tooling/1 невозможен: объявлены обозначения "
            "валюты в ячейке, а первая версия языка их не исполняет. "
            "Выбросить правило значило бы тихо изменить смысл разбора",
        )
    свой["язык"] = LEGACY_TOOLING_SCHEMA_VERSION
    return свой


def detect_version(artifact_type: str, source: Any) -> str:
    """Опознаёт только известную и полностью читаемую версию артефакта."""

    return read_artifact(artifact_type, source).schema_version


def read_record(source: Any) -> VersionedArtifact:
    return read_artifact(_RECORD, source)


def read_manifest(source: Any) -> VersionedArtifact:
    return read_artifact(_MANIFEST, source)


def read_journal(source: Any) -> VersionedArtifact:
    return read_artifact(_JOURNAL, source)


def verify_journal(source: Any, expected_head: str | None = None) -> str:
    """Проверяет цепь ``journal/1`` или ``journal/2`` и возвращает вершину."""

    artifact = read_journal(source)
    head = _validate_journal(artifact.data, artifact.schema_version)
    if expected_head is not None:
        expected_head = _validate_hash(expected_head, "expected_head", None)
        if not hmac.compare_digest(head, expected_head):
            _error(
                "E_HEAD_MISMATCH",
                "вершина цепи не совпала с ожидаемой",
            )
    return head


def canonical_journal_bytes(source: Any) -> bytes:
    """Возвращает проверенный журнал обеих версий как компактный JSON Lines."""

    artifact = read_journal(source)
    fields = (
        _JOURNAL_1_FIELDS
        if artifact.schema_version == LEGACY_JOURNAL_SCHEMA_VERSION
        else _JOURNAL_2_FIELDS
    )
    chunks: list[bytes] = []
    for entry in artifact.data:
        ordered = {field: entry[field] for field in fields}
        chunks.append(
            json.dumps(
                ordered,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    return b"".join(chunks)


def _upgrade_journal_1_to_2(entries: Any) -> list[dict[str, Any]]:
    source = _journal_entries(entries)
    previous_hash = journal_module.CHAIN_START
    result: list[dict[str, Any]] = []
    for sequence, entry in enumerate(source, start=1):
        payload = {field: copy.deepcopy(entry[field]) for field in _PAYLOAD_FIELDS}
        record_hash = _journal_hash(
            JOURNAL_SCHEMA_VERSION,
            payload,
            sequence,
            previous_hash,
        )
        result.append(
            {
                "schema_version": JOURNAL_SCHEMA_VERSION,
                "sequence": sequence,
                "previous_hash": previous_hash,
                **payload,
                "hash": record_hash,
            }
        )
        previous_hash = record_hash
    return result


def _downgrade_journal_2_to_1(entries: Any) -> list[dict[str, Any]]:
    source = _journal_entries(entries)
    previous_hash = journal_module.CHAIN_START
    result: list[dict[str, Any]] = []
    for sequence, entry in enumerate(source, start=1):
        payload = {field: copy.deepcopy(entry[field]) for field in _PAYLOAD_FIELDS}
        record_hash = _journal_hash(
            LEGACY_JOURNAL_SCHEMA_VERSION,
            payload,
            sequence,
            previous_hash,
        )
        result.append(
            {
                "sequence": sequence,
                "previous_hash": previous_hash,
                **payload,
                "hash": record_hash,
            }
        )
        previous_hash = record_hash
    return result


DEFAULT_REGISTRY = MigrationRegistry(
    (
        MigrationStep(
            _JOURNAL,
            LEGACY_JOURNAL_SCHEMA_VERSION,
            JOURNAL_SCHEMA_VERSION,
            "migration/journal-1-to-2/1",
            _upgrade_journal_1_to_2,
        ),
        MigrationStep(
            _JOURNAL,
            JOURNAL_SCHEMA_VERSION,
            LEGACY_JOURNAL_SCHEMA_VERSION,
            "migration/journal-2-to-1/1",
            _downgrade_journal_2_to_1,
        ),
        MigrationStep(
            _TOOLING,
            LEGACY_TOOLING_SCHEMA_VERSION,
            TOOLING_SCHEMA_VERSION,
            "migration/tooling-1-to-2/1",
            _tooling_1_to_2,
        ),
        MigrationStep(
            _TOOLING,
            TOOLING_SCHEMA_VERSION,
            LEGACY_TOOLING_SCHEMA_VERSION,
            "migration/tooling-2-to-1/1",
            _tooling_2_to_1,
        ),
    )
)


def _payloads(entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for record_number, entry in enumerate(entries, start=1):
        missing = [field for field in _PAYLOAD_FIELDS if field not in entry]
        if missing:
            _error(
                "E_PAYLOAD_CHANGED",
                f"после миграции исчезло поле record.{missing[0]}",
                record_number=record_number,
            )
        result.append(
            {field: copy.deepcopy(entry[field]) for field in _PAYLOAD_FIELDS}
        )
    return result


def _payload_fingerprint(payload: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise MigrationError(
            "E_PAYLOAD_CHANGED",
            "полезные поля после миграции нельзя сравнить без потерь",
        ) from exc


def _assert_journal_preserved(
    before: Sequence[Mapping[str, Any]],
    after: Sequence[Mapping[str, Any]],
) -> None:
    """Проверяет потерю, перестановку и искажение до проверки новой цепи."""

    if len(before) != len(after):
        _error(
            "E_RECORD_COUNT_CHANGED",
            "миграция изменила число записей журнала: "
            f"было {len(before)}, стало {len(after)}",
        )
    before_sequences = [entry.get("sequence") for entry in before]
    after_sequences = [entry.get("sequence") for entry in after]
    if before_sequences != after_sequences:
        _error(
            "E_RECORD_ORDER_CHANGED",
            "миграция изменила порядок записей журнала",
        )

    before_payloads = _payloads(before)
    after_payloads = _payloads(after)
    if before_payloads == after_payloads:
        return
    before_fingerprints = Counter(map(_payload_fingerprint, before_payloads))
    after_fingerprints = Counter(map(_payload_fingerprint, after_payloads))
    if before_fingerprints == after_fingerprints:
        _error(
            "E_RECORD_ORDER_CHANGED",
            "миграция переставила полезные данные записей журнала",
        )
    _error(
        "E_PAYLOAD_CHANGED",
        "миграция исказила полезные поля журнала",
    )


def _step_output_entries(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, VersionedArtifact):
        value = value.data
    if isinstance(value, MigrationResult):
        value = value.artifact
    return _journal_entries(value)


def migrate_artifact(
    artifact_type: str,
    source: Any,
    target_version: str | None = None,
    *,
    registry: MigrationRegistry = DEFAULT_REGISTRY,
) -> MigrationResult:
    """Мигрирует артефакт по цепочке реестра и проверяет каждый шаг."""

    artifact_type = _normalise_artifact_type(artifact_type)
    if not isinstance(registry, MigrationRegistry):
        _error(
            "E_INVALID_MIGRATION_REGISTRY",
            "registry должен быть объектом MigrationRegistry",
        )
    if target_version is None:
        target_version = CURRENT_VERSIONS[artifact_type]
    _require_known_version(artifact_type, target_version)

    history: tuple[MigrationRecord, ...] = ()
    previous_result: MigrationResult | None = None
    if isinstance(source, MigrationResult):
        previous_result = source
        history = source.migration_records
    artifact = read_artifact(artifact_type, source)
    initial_version = artifact.schema_version
    if initial_version == target_version:
        if previous_result is not None:
            return previous_result
        return MigrationResult(
            artifact_type,
            initial_version,
            target_version,
            copy.deepcopy(artifact.data),
            history,
        )

    route = registry.route(artifact_type, initial_version, target_version)
    current_data = artifact.data
    current_version = initial_version
    records = list(history)
    for step in route:
        if step.source_version != current_version:
            _error(
                "E_MIGRATION_ROUTE_BROKEN",
                "реестр вернул несвязную последовательность шагов",
            )
        before_data = copy.deepcopy(current_data)
        old_head: str | None = None
        before_count = 1
        if artifact_type == _JOURNAL:
            old_head = _validate_journal(before_data, current_version)
            before_count = len(before_data)
        try:
            transformed = step.transform(copy.deepcopy(before_data))
        except MigrationError:
            raise
        except Exception as exc:
            raise MigrationError(
                "E_MIGRATION_STEP_FAILED",
                f"шаг {step.migration_version!r} завершился ошибкой",
            ) from exc

        if artifact_type == _JOURNAL:
            candidate = _step_output_entries(transformed)
            _assert_journal_preserved(before_data, candidate)
        else:
            candidate = transformed
        checked = read_artifact(artifact_type, candidate)
        if checked.schema_version != step.target_version:
            _error(
                "E_MIGRATION_STEP_RESULT",
                "шаг миграции вернул не заявленную версию схемы",
            )

        new_head: str | None = None
        after_count = 1
        if artifact_type == _JOURNAL:
            new_head = _validate_journal(
                checked.data,
                checked.schema_version,
            )
            after_count = len(checked.data)
            # Проверка выполняется повторно уже над нормализованным результатом.
            _assert_journal_preserved(before_data, checked.data)
        records.append(
            MigrationRecord(
                artifact_type=artifact_type,
                migration_version=step.migration_version,
                source_version=step.source_version,
                target_version=step.target_version,
                old_head=old_head,
                new_head=new_head,
                record_count_before=before_count,
                record_count_after=after_count,
            )
        )
        current_data = checked.data
        current_version = checked.schema_version

    return MigrationResult(
        artifact_type,
        initial_version,
        current_version,
        copy.deepcopy(current_data),
        tuple(records),
    )


def migrate_record(
    source: Any,
    target_version: str = RECORD_SCHEMA_VERSION,
    *,
    registry: MigrationRegistry = DEFAULT_REGISTRY,
) -> MigrationResult:
    return migrate_artifact(
        _RECORD,
        source,
        target_version,
        registry=registry,
    )


def migrate_manifest(
    source: Any,
    target_version: str = MANIFEST_SCHEMA_VERSION,
    *,
    registry: MigrationRegistry = DEFAULT_REGISTRY,
) -> MigrationResult:
    return migrate_artifact(
        _MANIFEST,
        source,
        target_version,
        registry=registry,
    )


def migrate_journal(
    source: Any,
    target_version: str = JOURNAL_SCHEMA_VERSION,
    *,
    registry: MigrationRegistry = DEFAULT_REGISTRY,
) -> MigrationResult:
    return migrate_artifact(
        _JOURNAL,
        source,
        target_version,
        registry=registry,
    )


__all__ = [
    "CURRENT_VERSIONS",
    "DEFAULT_REGISTRY",
    "JOURNAL_SCHEMA_VERSION",
    "LEGACY_JOURNAL_SCHEMA_VERSION",
    "MANIFEST_SCHEMA_VERSION",
    "MIGRATION_RECORD_SCHEMA_VERSION",
    "MigrationError",
    "MigrationRecord",
    "MigrationRegistry",
    "MigrationResult",
    "MigrationStep",
    "RECORD_SCHEMA_VERSION",
    "SCHEMA_VERSIONS",
    "VersionedArtifact",
    "canonical_journal_bytes",
    "detect_version",
    "migrate_artifact",
    "migrate_journal",
    "migrate_manifest",
    "migrate_record",
    "read_artifact",
    "read_journal",
    "read_manifest",
    "read_record",
    "verify_journal",
]
