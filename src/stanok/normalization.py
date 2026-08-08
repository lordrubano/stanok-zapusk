"""Детерминированная нормализация текста по правилам шаблона.

Без явного правила поля текст приводится только к NFC. Совместимостная
нормализация NFKC задаётся исключительно для именованного поля и оставляет в
результате отдельный признак изменения относительно NFC. Пробелы и управляющие
символы обрабатываются независимыми, по умолчанию выключенными настройками.

Модуль не разбирает даты, числа и валюты, не выполняет обратную сериализацию и
не зависит от канонического сериализатора записей.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from types import MappingProxyType
from typing import Never


KNOWN_POLICY_VERSIONS = frozenset({"normalization/1"})


class NormalizationError(ValueError):
    """Ошибка политики или выполнения нормализации текста."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _error(code: str, message: str) -> Never:
    raise NormalizationError(code, message)


class FieldKind(StrEnum):
    """Вид поля, влияющий на допустимость совместимостной свёртки."""

    TEXT = "text"
    MONEY = "money"
    IDENTIFIER = "identifier"


_SENSITIVE_FIELD_KINDS = frozenset({FieldKind.MONEY, FieldKind.IDENTIFIER})


@dataclass(frozen=True, slots=True)
class FieldNormalizationRule:
    """Текстовые преобразования для одного конкретного поля шаблона.

    ``unicode_form=None`` означает наследование безопасного NFC политики.
    NFKC разрешён только при явном значении ``"NFKC"`` в таком правиле.
    """

    unicode_form: str | None = None
    normalize_spaces: bool = False
    remove_control_characters: bool = False
    field_kind: FieldKind | str = FieldKind.TEXT
    risk_acknowledged: bool = False

    def __post_init__(self) -> None:
        if self.unicode_form not in (None, "NFC", "NFKC"):
            _error(
                "E_INVALID_UNICODE_FORM",
                f"неподдерживаемая форма Unicode в правиле: {self.unicode_form!r}",
            )
        if not isinstance(self.normalize_spaces, bool):
            _error(
                "E_INVALID_RULE",
                "признак нормализации пробелов должен быть логическим",
            )
        if not isinstance(self.remove_control_characters, bool):
            _error(
                "E_INVALID_RULE",
                "признак удаления управляющих символов должен быть логическим",
            )
        if not isinstance(self.risk_acknowledged, bool):
            _error(
                "E_INVALID_RULE",
                "признание риска должно быть логическим",
            )
        try:
            kind = FieldKind(self.field_kind)
        except (TypeError, ValueError) as exc:
            raise NormalizationError(
                "E_INVALID_FIELD_KIND",
                f"неизвестный вид поля: {self.field_kind!r}",
            ) from exc
        object.__setattr__(self, "field_kind", kind)


@dataclass(frozen=True, slots=True)
class NormalizationPolicy:
    """Версионированная политика нормализации полей шаблона."""

    version: str
    owner: str
    approved_on: date
    default_unicode_form: str = "NFC"
    field_rules: Mapping[str, FieldNormalizationRule] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.default_unicode_form == "NFKC":
            _error(
                "E_NFKC_AS_DEFAULT_FORBIDDEN",
                "NFKC запрещён как форма Unicode по умолчанию",
            )
        if self.default_unicode_form != "NFC":
            _error(
                "E_INVALID_UNICODE_FORM",
                "формой Unicode по умолчанию должен быть NFC",
            )
        if (
            not isinstance(self.version, str)
            or self.version not in KNOWN_POLICY_VERSIONS
        ):
            _error(
                "E_UNKNOWN_POLICY_VERSION",
                f"неизвестная версия политики: {self.version!r}",
            )
        if not isinstance(self.owner, str) or not self.owner.strip():
            _error("E_INVALID_POLICY", "владелец политики должен быть указан")
        if not isinstance(self.approved_on, date):
            _error(
                "E_INVALID_POLICY",
                "дата утверждения политики должна иметь тип date",
            )
        if not isinstance(self.field_rules, Mapping):
            _error("E_INVALID_POLICY", "правила полей должны быть отображением")

        copied_rules: dict[str, FieldNormalizationRule] = {}
        for field_name, rule in self.field_rules.items():
            if not isinstance(field_name, str) or not field_name:
                _error("E_INVALID_POLICY", "имя поля в политике должно быть строкой")
            if not isinstance(rule, FieldNormalizationRule):
                _error(
                    "E_INVALID_POLICY",
                    f"правило поля {field_name!r} имеет неверный тип",
                )
            copied_rules[field_name] = rule
        object.__setattr__(self, "field_rules", MappingProxyType(copied_rules))


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    """Исходный и нормализованный текст вместе с происхождением результата."""

    raw: str
    normalized: str
    policy_version: str
    nfkc_changed: bool


_DEFAULT_FIELD_RULE = FieldNormalizationRule()


def _normalize_spaces(value: str) -> str:
    """Приводит NBSP/NNBSP к пробелу, схлопывает и обрезает пробелы."""

    ordinary_spaces = value.replace("\N{NO-BREAK SPACE}", " ").replace(
        "\N{NARROW NO-BREAK SPACE}", " "
    )
    return re.sub(r" +", " ", ordinary_spaces).strip(" ")


def _remove_control_characters(value: str) -> str:
    """Удаляет символы общей категории Unicode Cc."""

    return "".join(
        character
        for character in value
        if unicodedata.category(character) != "Cc"
    )


def normalize_text(
    raw: str,
    field_name: str,
    policy: NormalizationPolicy,
) -> NormalizationResult:
    """Нормализует текст именованного поля, не изменяя исходное значение.

    Признак ``nfkc_changed`` истинен, только когда результат NFKC отличается
    от результата безопасного NFC для той же исходной строки. Он вычисляется
    до включённых правил пробелов и управляющих символов, поэтому такая
    совместимостная подмена не может раствориться среди других преобразований.
    """

    if not isinstance(raw, str):
        _error("E_INVALID_TEXT_TYPE", "исходное значение должно быть строкой")
    if not isinstance(field_name, str) or not field_name:
        _error("E_INVALID_FIELD_NAME", "имя поля должно быть непустой строкой")
    if not isinstance(policy, NormalizationPolicy):
        _error("E_INVALID_POLICY", "ожидалась политика нормализации")

    rule = policy.field_rules.get(field_name, _DEFAULT_FIELD_RULE)
    unicode_form = rule.unicode_form or policy.default_unicode_form
    if (
        unicode_form == "NFKC"
        and rule.field_kind in _SENSITIVE_FIELD_KINDS
        and not rule.risk_acknowledged
    ):
        _error(
            "E_NFKC_ON_SENSITIVE_FIELD",
            f"NFKC для чувствительного поля {field_name!r} требует признания риска",
        )

    nfc_value = unicodedata.normalize("NFC", raw)
    if unicode_form == "NFKC":
        normalized = unicodedata.normalize("NFKC", raw)
        nfkc_changed = normalized != nfc_value
    else:
        normalized = nfc_value
        nfkc_changed = False

    if rule.remove_control_characters:
        normalized = _remove_control_characters(normalized)
    if rule.normalize_spaces:
        normalized = _normalize_spaces(normalized)

    return NormalizationResult(
        raw=raw,
        normalized=normalized,
        policy_version=policy.version,
        nfkc_changed=nfkc_changed,
    )
