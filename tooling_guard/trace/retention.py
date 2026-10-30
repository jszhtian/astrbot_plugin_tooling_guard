"""Trajectory retention: keep only the most recent records per subject.

Requirement: Retention and Rotation; Trajectory Window.

The trajectory window is the most recent 50 summary records per subject, so this
trim helper is the single place that decides what survives.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypeVar

DEFAULT_KEEP = 50

Item = TypeVar("Item")


def trim_for_subject(items: Sequence[Item], keep: int = DEFAULT_KEEP) -> list[Item]:
    """Keep the most recent keep items, preserving their order.

    Requirement: Retention and Rotation; Trajectory Window.

    Args:
        items: Records in ascending age order (oldest first).
        keep: Number of most recent records to keep (default 50).

    Returns:
        list[Item]: The trailing keep items, oldest first.

    Raises:
        ValueError: When keep is negative.
    """
    if keep < 0:
        raise ValueError(f"keep must be >= 0, got {keep}")
    if keep == 0:
        return []
    if len(items) <= keep:
        return list(items)
    return list(items[-keep:])
