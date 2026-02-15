from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Tuple


Severity = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class SeverityThresholds:
    high: float = 0.85
    medium: float = 0.60


def severity_from_score(score: float, thresholds: SeverityThresholds) -> Severity:
    if score >= thresholds.high:
        return "high"
    if score >= thresholds.medium:
        return "medium"
    return "low"


def decide_actions(
    threats: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    enabled: bool = True,
    dry_run: bool = True,
    default_block_minutes: int = 60,
) -> List[Dict[str, Any]]:
    """
    Deterministic policy engine (production-friendly baseline).
    Can later be replaced by LLM / planner.
    """
    if not enabled:
        return [{"type": "noop", "reason": "response_disabled"}]

    actions: List[Dict[str, Any]] = []

    # Block malicious destination IPs for high/medium threats
    for t in threats:
        sev = t.get("severity", "low")
        if sev in {"high", "medium"}:
            ip = t.get("dst_ip") or t.get("ip")
            if ip:
                actions.append(
                    {
                        "type": "block_ip",
                        "ip": ip,
                        "duration_minutes": int(t.get("duration_minutes", default_block_minutes)),
                        "dry_run": dry_run,
                        "reason": f"threat_{sev}",
                    }
                )

    # For repeated anomalies, isolate host (demo heuristic)
    high_anoms = [a for a in anomalies if float(a.get("score", 0.0)) >= 0.85]
    if len(high_anoms) >= 3:
        # pick most common src_ip
        counts: Dict[str, int] = {}
        for a in high_anoms:
            ip = a.get("src_ip")
            if ip:
                counts[str(ip)] = counts.get(str(ip), 0) + 1
        if counts:
            src_ip = sorted(counts.items(), key=lambda x: x[1], reverse=True)[0][0]
            actions.append(
                {
                    "type": "isolate_host",
                    "ip": src_ip,
                    "duration_minutes": 15,
                    "dry_run": dry_run,
                    "reason": "repeated_high_anomalies",
                }
            )

    if not actions:
        actions.append({"type": "noop", "reason": "no_action_needed"})
    return actions


def summarize_decision(threats: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]) -> Tuple[str, float]:
    """
    Returns a compact status and max_score.
    """
    max_t = max([float(t.get("score", 0.0)) for t in threats] + [0.0])
    max_a = max([float(a.get("score", 0.0)) for a in anomalies] + [0.0])
    m = max(max_t, max_a)
    if m >= 0.85:
        return "high_risk", m
    if m >= 0.60:
        return "elevated_risk", m
    return "normal", m






