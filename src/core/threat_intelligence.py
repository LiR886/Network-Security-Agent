from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx


logger = logging.getLogger(__name__)


@dataclass
class FeedConfig:
    name: str
    url: str
    type: str  # ip_list (demo)
    refresh_minutes: int = 360


class ThreatIntel:
    """
    In-memory TI cache backed by:
    - local JSON file (seed)
    - external feeds (periodic refresh)
    """

    def __init__(self, local_db_path: str, feeds: List[FeedConfig], cache_ttl_minutes: int = 360):
        self.local_db_path = Path(local_db_path)
        self.feeds = feeds
        self.cache_ttl_s = cache_ttl_minutes * 60

        self._loaded_at: float = 0.0
        self._malicious_ips: Dict[str, Dict[str, Any]] = {}
        self._signatures: List[Dict[str, Any]] = []
        self._feed_ips: Set[str] = set()
        self._lock = asyncio.Lock()

    async def ensure_loaded(self) -> None:
        async with self._lock:
            now = time.time()
            if self._loaded_at and (now - self._loaded_at) < self.cache_ttl_s:
                return
            await self._load_local()
            await self._refresh_feeds()
            self._loaded_at = now

    async def _load_local(self) -> None:
        if not self.local_db_path.exists():
            logger.warning("threat_intel_local_db_missing", extra={"path": str(self.local_db_path)})
            self._malicious_ips = {}
            self._signatures = []
            return

        raw = json.loads(self.local_db_path.read_text(encoding="utf-8"))
        ips = raw.get("malicious_ips", []) or []
        self._malicious_ips = {e["ip"]: e for e in ips if "ip" in e}
        self._signatures = list(raw.get("signatures", []) or [])

    async def _refresh_feeds(self) -> None:
        if not self.feeds:
            self._feed_ips = set()
            return

        out: Set[str] = set()
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for f in self.feeds:
                try:
                    if (f.type or "").lower() != "ip_list":
                        continue
                    txt = (await client.get(f.url)).text
                    for line in txt.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # firehol-style lists can include CIDRs; keep simple IPs for demo
                        if "/" in line:
                            continue
                        out.add(line)
                except Exception as e:
                    logger.warning("threat_intel_feed_failed", extra={"feed": f.name, "err": str(e)})
        self._feed_ips = out

    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        return self._malicious_ips.get(ip)

    def is_feed_malicious(self, ip: str) -> bool:
        return ip in self._feed_ips

    def match_signatures(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for sig in self._signatures:
            match = sig.get("match", {}) or {}
            ok = True
            for k, v in match.items():
                if packet.get(k) != v:
                    ok = False
                    break
            if ok:
                hits.append(sig)
        return hits

    def score_packet(self, packet: Dict[str, Any]) -> Tuple[float, List[str], List[Dict[str, Any]]]:
        """
        Returns: (score in 0..1, tags, evidence)
        """
        tags: List[str] = []
        evidence: List[Dict[str, Any]] = []
        score = 0.0

        dst_ip = str(packet.get("dst_ip", "") or "")
        if dst_ip:
            local = self.lookup_ip(dst_ip)
            if local:
                score = max(score, float(local.get("severity", 0.8)))
                tags.extend(list(local.get("tags", []) or []))
                evidence.append({"type": "ti_local_ip", "data": local})
            if self.is_feed_malicious(dst_ip):
                score = max(score, 0.8)
                tags.append("ti_feed_ip")
                evidence.append({"type": "ti_feed_ip", "ip": dst_ip})

        sig_hits = self.match_signatures(packet)
        for s in sig_hits:
            score = max(score, float(s.get("severity", 0.6)))
            if "tag" in s:
                tags.append(str(s["tag"]))
            evidence.append({"type": "signature", "data": s})

        # normalize tags
        tags = sorted(set([t for t in tags if t]))
        return min(score, 1.0), tags, evidence






