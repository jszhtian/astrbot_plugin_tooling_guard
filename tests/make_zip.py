"""Package this plugin as a release zip: python tests/make_zip.py <version>."""
import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {"__pycache__", "tests", "openspec", ".git", ".idea", ".vscode"}
SKIP_SUFFIX = (".pyc", ".pyo", ".sqlite3", ".log", ".zip")


def package(version: str) -> Path:
    out = ROOT.parent / ("astrbot_plugin_tooling_guard-" + version + ".zip")
    count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for base, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for name in sorted(files):
                if name.endswith(SKIP_SUFFIX):
                    continue
                full = Path(base) / name
                arc = Path(ROOT.name) / full.relative_to(ROOT)
                zf.write(full, arc.as_posix())
                count += 1
    print("entries:", count, "->", out)
    return out


if __name__ == "__main__":
    package(sys.argv[1] if len(sys.argv) > 1 else "0.0.0")
