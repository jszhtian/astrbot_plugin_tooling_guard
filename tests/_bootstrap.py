"""Shared test bootstrap: repo root on sys.path, plus a secret-free config fixture.

Every harness starts with:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _bootstrap import fixture_config

so the suite runs from a fresh clone with no environment variables and no local
AstrBot install. The fixture never contains a real API key, admin id or host.
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE = TESTS / "fixtures" / "config.example.json"


def fixture_config():
    """Return (raw config, temp dir) with project_roots pointing at real temp dirs."""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    tmp = Path(tempfile.mkdtemp(prefix="tgfix_"))
    roots = [tmp / "plugin_data", tmp / "temp", tmp / "workspaces"]
    for item in roots:
        item.mkdir(parents=True, exist_ok=True)
    raw["project_roots"] = [str(item) for item in roots]
    return raw, tmp
