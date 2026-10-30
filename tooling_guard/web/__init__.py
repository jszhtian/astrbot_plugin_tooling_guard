"""Dashboard plugin page: host-registered JSON endpoints.

Requirement: Plugin Page Presence. The page itself is the static file under
`views/guard/index.html`; this package only registers routes, resolves who may
read and write what, and forwards a decision to the ticket CAS the command plane
already uses.
"""

from __future__ import annotations

from .api import AUDIT_TOOL, REFUSAL_RULE, make_views, register_web_apis
from .queries import QueryError, Scope, resolve_scope

__all__ = [
    "AUDIT_TOOL",
    "REFUSAL_RULE",
    "QueryError",
    "Scope",
    "make_views",
    "register_web_apis",
    "resolve_scope",
]
