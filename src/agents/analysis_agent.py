from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from ..core.threat_intelligence import ThreatIntel
from ..models.anomaly_detection import AnomalyDetector


@dataclass
class AnalysisAgent:
    threat_intel: ThreatIntel
    anomaly_detector: AnomalyDetector

    async def score_threat_intel(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        await self.threat_intel.ensure_loaded()
        out: List[Dict[str, Any]] = []
        for i, pkt in enumerate(packets):
            score, tags, evidence = self.threat_intel.score_packet(pkt)
            if score > 0:
                out.append({"packet_idx": i, "score": score, "tags": tags, "evidence": evidence})
        return out

    async def detect_anomalies(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self.anomaly_detector.score_packets(packets)






