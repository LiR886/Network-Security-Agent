from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from ..core.decision_engine import Severity, SeverityThresholds, severity_from_score


@dataclass(frozen=True)
class ThreatDetectionConfig:
    thresholds: SeverityThresholds = SeverityThresholds()


def classify_threats(
    packets: List[Dict[str, Any]],
    ti_scores: List[Dict[str, Any]],
    thresholds: SeverityThresholds,
) -> List[Dict[str, Any]]:
    """
    Combine TI signals and (later) ML signals into threat records.

    `ti_scores` is list of dicts: {packet_idx, score, tags, evidence}
    """
    out: List[Dict[str, Any]] = []
    for item in ti_scores:
        i = int(item.get("packet_idx", -1))
        if i < 0 or i >= len(packets):
            continue
        pkt = packets[i]
        score = float(item.get("score", 0.0))
        sev: Severity = severity_from_score(score, thresholds)
        if sev == "low":
            continue
        out.append(
            {
                "score": score,
                "severity": sev,
                "tags": item.get("tags", []),
                "evidence": item.get("evidence", []),
                "src_ip": pkt.get("src_ip"),
                "dst_ip": pkt.get("dst_ip"),
                "dst_port": pkt.get("dst_port"),
                "proto": pkt.get("proto"),
            }
        )
    return out






