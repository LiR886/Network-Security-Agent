from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from ..core.packet_analyzer import CaptureConfig, capture_packets


@dataclass
class MonitoringAgent:
    cfg: CaptureConfig

    async def stream(self):
        async for batch in capture_packets(self.cfg):
            yield batch






