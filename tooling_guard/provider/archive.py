"""Deep-review task archive via existing redacted trajectory storage.
Requirement: Sanitized Persistence; Sync and Async Review.
"""

from __future__ import annotations

import json
from typing import Any

from ..anonymize import Anonymizer, PathRedactor
from ..store.audit import record_trajectory_snippet


def archive_result(store: Any, task_id: str, result: Any) -> None:
    """Persist one review result after shared secret and path redaction.

    Existing API: record_trajectory_snippet(conn, *, subject_key, summary,
    ...); store is the SQLite connection. Serialize and redact before writing.
    """
    text = json.dumps(result, ensure_ascii=False, sort_keys=True, default=str)
    redacted = Anonymizer(paths=PathRedactor()).redact(text)
    record_trajectory_snippet(store, subject_key=task_id, summary=redacted)
