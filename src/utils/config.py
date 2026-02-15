from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import os
import yaml


@dataclass(frozen=True)
class AppConfig:
    raw: Dict[str, Any]

    def get(self, *keys: str, default: Any = None) -> Any:
        cur: Any = self.raw
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    @property
    def api_key(self) -> str:
        return str(self.raw.get("app", {}).get("api_key", "change-me"))

    @property
    def database_url(self) -> str:
        return os.getenv("DATABASE_URL") or str(self.raw.get("storage", {}).get("url"))


_CONFIG_CACHE: Optional[AppConfig] = None


def load_config(path: Optional[str] = None) -> AppConfig:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE

    cfg_path = path or os.getenv("NSA_CONFIG") or "./config.yaml"
    p = Path(cfg_path).expanduser().resolve()
    with p.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    _CONFIG_CACHE = AppConfig(raw=raw)
    return _CONFIG_CACHE


