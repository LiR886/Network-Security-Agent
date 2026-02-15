import os
import sys
from pathlib import Path


def pytest_configure():
    # allow `from src...` imports when running tests from repo root or project dir
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    os.environ.setdefault("NSA_CONFIG", str(root / "config.yaml"))






