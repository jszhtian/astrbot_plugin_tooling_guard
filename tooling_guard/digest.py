"""Canonical argument digest and bounded argument head.

Requirement: Argument Digesting; Ticket Persistence.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping
from typing import Any, Final

#: Truncated digest width: first 16 bytes rendered as 32 lowercase hex characters.
DIGEST_HEX_CHARS = 32

#: Hard cap on the stored argument head, in characters.
ARGS_HEAD_LIMIT = 512

#: Marker key for a value that has no stable JSON number form.
_NON_FINITE_MARKER: Final[str] = "$non_finite"

#: Marker key wrapping an unordered collection rendered in sorted order.
_SET_MARKER: Final[str] = "$set"


def _declared_properties(schema: Any) -> Mapping[str, Any] | None:
    """Return the properties mapping a tool schema declares.

    Args:
        schema: Tool parameters mapping, or anything else.

    Returns:
        The declared property mapping, an empty mapping for a schema that
        declares no properties, or None when no schema is available at all.
    """
    if not isinstance(schema, Mapping):
        return None
    properties = schema.get("properties")
    return properties if isinstance(properties, Mapping) else None


def canonical_arguments(schema: Any, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce arguments to the exact key set the tool schema declares.

    Requirement: Argument Digesting.

    Args:
        schema: Tool parameters mapping used for the key set and defaults.
        arguments: Raw arguments supplied by the runner.

    Returns:
        A new dict holding every schema-declared key: the supplied value when
        present, otherwise the schema default when declared, otherwise None.
        Keys the schema does not declare are dropped. Without a schema the
        supplied keys are kept as they are, so callers that only observe a call
        (intent records, trajectory entries) still hash the same call the same
        way the proxy does.
    """
    declared = _declared_properties(schema)
    if declared is None:
        return {str(key): arguments[key] for key in arguments}
    canonical: dict[str, Any] = {}
    for key, spec in declared.items():
        if key in arguments:
            canonical[key] = arguments[key]
            continue
        default = spec.get("default") if isinstance(spec, Mapping) else None
        canonical[key] = default
    return canonical


def _stable_key(value: Any) -> str:
    """Return a total-order key for already normalized values of mixed types."""
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    )


def _normalize(value: Any) -> Any:
    """Normalize one value for stable JSON encoding.

    Args:
        value: Any argument value.

    Returns:
        Booleans, None and ints unchanged, strings normalized to NFKC and then
        NFC so equal text hashes equally, floats normalized so an integral
        finite float becomes the equal int and -0.0 becomes 0, non-finite floats
        and unordered collections wrapped in a stable marker form, mappings and
        sequences normalized recursively, everything else reduced to its string
        form.

        The two passes are ordered, not redundant: NFKC folds compatibility
        variants (full-width digits, the Kelvin sign, ligatures) that NFC leaves
        alone, and NFC stays last so everything downstream still sees the
        composed form it already expected. The composition is idempotent because
        NFKC of an already composed NFKC text is that same text.
    """
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", unicodedata.normalize("NFKC", value))
    if isinstance(value, float):
        if value == 0:
            return 0
        if math.isfinite(value):
            return int(value) if value.is_integer() else value
        if math.isnan(value):
            return {_NON_FINITE_MARKER: "nan"}
        return {_NON_FINITE_MARKER: "inf" if value > 0 else "-inf"}
    if isinstance(value, Mapping):
        return {_normalize(str(key)): _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_normalize(item) for item in value]
        return {_SET_MARKER: sorted(items, key=_stable_key)}
    return str(value)


def canonical_json(schema: Any, arguments: Mapping[str, Any]) -> str:
    """Encode canonical arguments as key-sorted compact JSON.

    Requirement: Argument Digesting.

    Args:
        schema: Tool parameters mapping.
        arguments: Raw arguments supplied by the runner.

    Returns:
        Compact JSON with sorted keys, schema defaults filled in and numbers
        normalized, so two equal calls always encode to the same string.
    """
    return json.dumps(
        _normalize(canonical_arguments(schema, arguments)),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    )


def args_digest(schema: Any, arguments: Mapping[str, Any]) -> str:
    """Return the truncated SHA-256 digest that binds one exact call.

    Requirement: Argument Digesting; Approved Retry Exemption.

    Args:
        schema: Tool parameters mapping.
        arguments: Raw arguments supplied by the runner.

    Returns:
        The first 16 bytes of the SHA-256 over canonical_json, as 32 lowercase
        hexadecimal characters. Every module that binds a ticket, an intent
        record or a trajectory entry to one call must use this function so the
        same call always yields the same digest.
    """
    payload = canonical_json(schema, arguments).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:DIGEST_HEX_CHARS]


def args_head(arguments: Mapping[str, Any], limit: int = ARGS_HEAD_LIMIT) -> str:
    """Return a bounded, single-line head of the raw arguments.

    Requirement: Argument Digesting.

    Args:
        arguments: Raw arguments supplied by the runner.
        limit: Maximum number of characters kept.

    Returns:
        At most limit characters of a compact single-line rendering. Callers
        must pass already-redacted arguments: redaction happens before this call.
    """
    text = " ".join(
        json.dumps(dict(arguments), ensure_ascii=False, default=str).split()
    )
    return text[: max(0, int(limit))]


def args_summary(schema: Any, arguments: Mapping[str, Any]) -> tuple[str, str]:
    """Return the args_digest and args_head pair stored per call.

    Requirement: Argument Digesting.

    Args:
        schema: Tool parameters mapping.
        arguments: Already-redacted raw arguments.

    Returns:
        The canonical digest and the bounded head, ready for a trajectory entry
        or a ticket row.
    """
    return args_digest(schema, arguments), args_head(arguments)
