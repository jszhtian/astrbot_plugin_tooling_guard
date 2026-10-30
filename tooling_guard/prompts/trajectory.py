"""Build bounded deep-review prompts from sanitized trajectory records.

Requirement: Deep Analysis Input Budget. Excerpts are limited to three items,
each no larger than 2 KiB, as specified by that requirement.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from ..anonymize import Anonymizer, PathRedactor

MAX_EXCERPTS = 3
MAX_EXCERPT_BYTES = 2 * 1024
MAX_SUMMARY_BYTES = 16 * 1024
SUMMARY_FIELDS = (
    "ts_seq",
    "call_id",
    "at",
    "user",
    "session",
    "tool",
    "origin",
    "verb",
    "targets",
    "tier",
    "args_digest",
    "args_head",
    "content_len",
    "content_lines",
    "rule_hits",
    "single",
    "links",
    "summary_line",
    "decision",
    "ticket",
    "labels",
    "delegated",
)
REQUIRED_LABELS = (
    "T-strong",
    "T-weak",
    "untrusted_source",
    "sink_read",
    "sink_deliver",
)


def _plain_record(item: Any) -> dict[str, Any]:
    """Convert supported trajectory summary objects to their public fields."""
    if callable(getattr(item, "as_dict", None)):
        item = item.as_dict()
    elif hasattr(item, "__dict__") and not isinstance(item, Mapping):
        item = vars(item)
    if not isinstance(item, Mapping):
        return {"summary_line": str(item)}
    return {key: item[key] for key in SUMMARY_FIELDS if key in item}


def build_trajectory_prompt(summary: Any) -> str:
    """Build a bounded prompt with only redacted summaries and excerpts.

    Implements OpenSpec Deep Analysis Input Budget: preserve T-strong/T-weak,
    untrusted_source, sink_read, and sink_deliver labels; include at most three
    non-secret excerpts of 2 KiB each; explicitly report inputs discarded for
    either boundary. Oversized excerpts are dropped whole, never silently cut.
    """
    anonymizer = Anonymizer(paths=PathRedactor())
    if isinstance(summary, Sequence) and not isinstance(summary, (str, bytes)):
        raw_records = list(summary)
        metadata: Mapping[str, Any] = {}
    else:
        metadata = summary if isinstance(summary, Mapping) else {}
        raw_records = metadata.get("summaries", metadata.get("records", [summary]))
        if not isinstance(raw_records, Sequence) or isinstance(
            raw_records, (str, bytes)
        ):
            raw_records = [summary]

    labels_seen: set[str] = set()
    records: list[dict[str, Any]] = []
    summary_dropped = 0
    for item in raw_records:
        record = anonymizer.redact_mapping(_plain_record(item))
        record_labels = record.get("labels", ())
        if isinstance(record_labels, str):
            record_labels = [record_labels]
        if isinstance(record_labels, Sequence):
            labels_seen.update(str(label) for label in record_labels)
        if record.get("tier") in {"T-strong", "T-weak"}:
            labels_seen.add(record["tier"])
        clean = json.loads(json.dumps(record, ensure_ascii=False, default=str))
        proposed = records + [clean]
        labels = {label: label in labels_seen for label in REQUIRED_LABELS}
        encoded = json.dumps(
            {"labels": labels, "summaries": proposed},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if len(encoded.encode("utf-8")) > MAX_SUMMARY_BYTES:
            summary_dropped += 1
            continue
        records.append(clean)

    labels = {label: label in labels_seen for label in REQUIRED_LABELS}
    summary_text = json.dumps(
        {"labels": labels, "summaries": records},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    candidates = metadata.get("excerpts", ())
    if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes)):
        candidates = ()
    excerpts: list[str] = []
    dropped = 0
    for candidate in candidates:
        if len(excerpts) >= MAX_EXCERPTS:
            dropped += 1
            continue
        value = (
            candidate.get("text", "") if isinstance(candidate, Mapping) else candidate
        )
        excerpt = anonymizer.redact(str(value))
        if len(excerpt.encode("utf-8")) > MAX_EXCERPT_BYTES:
            dropped += 1
            continue
        excerpts.append(excerpt)
    lines = ["Deep analysis trajectory (anonymized):", summary_text, "Excerpts:"]
    lines.extend(f"[{index + 1}] {excerpt}" for index, excerpt in enumerate(excerpts))
    lines.append(
        f"Dropped out-of-bounds inputs: {dropped} excerpt(s); "
        f"summary records discarded: {summary_dropped}."
    )
    return "\n".join(lines)
