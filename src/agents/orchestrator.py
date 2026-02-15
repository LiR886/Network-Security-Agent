from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, StateGraph

from ..core.decision_engine import SeverityThresholds, decide_actions, severity_from_score, summarize_decision
from ..core.packet_analyzer import CaptureConfig
from ..core.alerts import AlertManager, EmailConfig, SlackConfig, TelegramConfig
from ..core.storage import Storage
from ..core.threat_intelligence import FeedConfig, ThreatIntel
from ..models.anomaly_detection import AnomalyConfig, AnomalyDetector
from ..models.threat_detection import classify_threats
from ..utils.config import load_config
from ..utils.logger import setup_logging
from .analysis_agent import AnalysisAgent
from .monitoring_agent import MonitoringAgent
from .response_agent import ResponseAgent


logger = logging.getLogger(__name__)


class SecurityState(TypedDict, total=False):
    network_packets: List[Dict[str, Any]]
    detected_anomalies: List[Dict[str, Any]]
    ti_scores: List[Dict[str, Any]]
    threats: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    actions_taken: List[Dict[str, Any]]
    report: Dict[str, Any]
    risk_level: str
    max_score: float


def build_security_agent_graph(
    analysis_agent: AnalysisAgent,
    response_agent: ResponseAgent,
    thresholds: SeverityThresholds,
    response_enabled: bool,
    dry_run: bool,
):
    graph = StateGraph(SecurityState)

    async def capture_traffic(state: SecurityState) -> SecurityState:
        # capture handled outside graph; keep node for completeness
        return state

    async def analyze_packets(state: SecurityState) -> SecurityState:
        pkts = state.get("network_packets", []) or []
        ti_scores = await analysis_agent.score_threat_intel(pkts)
        return {**state, "ti_scores": ti_scores}

    async def detect_anomalies(state: SecurityState) -> SecurityState:
        pkts = state.get("network_packets", []) or []
        anomalies = await analysis_agent.detect_anomalies(pkts)
        return {**state, "detected_anomalies": anomalies}

    async def classify_threat(state: SecurityState) -> SecurityState:
        pkts = state.get("network_packets", []) or []
        ti_scores = state.get("ti_scores", []) or []
        threats = classify_threats(pkts, ti_scores, thresholds)
        # derive overall risk
        max_t = max([float(t.get("score", 0.0)) for t in threats] + [0.0])
        max_a = max([float(a.get("score", 0.0)) for a in (state.get("detected_anomalies", []) or [])] + [0.0])
        max_score = max(max_t, max_a)
        sev = severity_from_score(max_score, thresholds)
        risk_level = "high" if sev == "high" else ("medium" if sev == "medium" else "low")
        return {**state, "threats": threats, "risk_level": risk_level, "max_score": max_score}

    async def decide_response_node(state: SecurityState) -> SecurityState:
        threats = state.get("threats", []) or []
        anomalies = state.get("detected_anomalies", []) or []
        actions = decide_actions(threats, anomalies, enabled=response_enabled, dry_run=dry_run)
        return {**state, "actions": actions}

    async def execute_response_node(state: SecurityState) -> SecurityState:
        actions = state.get("actions", []) or []
        actions_taken = await response_agent.execute(actions)
        return {**state, "actions_taken": actions_taken}

    async def generate_report(state: SecurityState) -> SecurityState:
        threats = state.get("threats", []) or []
        anomalies = state.get("detected_anomalies", []) or []
        status, max_score = summarize_decision(threats, anomalies)
        # simple remediation hint
        if status == "high_risk":
            remediation = (
                "High risk activity detected. Block offending IPs at perimeter firewall, "
                "review SSH/auth logs on targeted hosts, and consider temporary host isolation."
            )
        elif status == "elevated_risk":
            remediation = (
                "Elevated risk. Review traffic patterns and logs for the listed IPs and ports; "
                "tighten ACLs if activity is unexpected."
            )
        else:
            remediation = "Normal risk level. No immediate action required."

        top_threats = sorted(threats, key=lambda t: float(t.get("score", 0.0)), reverse=True)[:5]
        top_anoms = sorted(anomalies, key=lambda a: float(a.get("score", 0.0)), reverse=True)[:5]

        report = {
            "status": status,
            "max_score": float(max_score),
            "threat_count": len(threats),
            "anomaly_count": len(anomalies),
            "actions": state.get("actions_taken", []) or state.get("actions", []) or [],
            "top_threats": top_threats,
            "top_anomalies": top_anoms,
            "remediation_hint": remediation,
        }
        return {**state, "report": report}

    graph.add_node("capture_traffic", capture_traffic)
    graph.add_node("analyze_packets", analyze_packets)
    graph.add_node("detect_anomalies", detect_anomalies)
    graph.add_node("classify_threat", classify_threat)
    graph.add_node("decide_response", decide_response_node)
    graph.add_node("execute_response", execute_response_node)
    graph.add_node("generate_report", generate_report)

    graph.set_entry_point("capture_traffic")
    graph.add_edge("capture_traffic", "analyze_packets")
    graph.add_edge("analyze_packets", "detect_anomalies")
    graph.add_edge("detect_anomalies", "classify_threat")

    # branch: low risk -> report; medium/high -> decide/execute -> report
    def _route_after_classify(state: SecurityState) -> str:
        return "respond" if state.get("risk_level") in {"medium", "high"} else "report"

    graph.add_conditional_edges(
        "classify_threat",
        _route_after_classify,
        {"respond": "decide_response", "report": "generate_report"},
    )

    graph.add_edge("decide_response", "execute_response")
    graph.add_edge("execute_response", "generate_report")
    graph.add_edge("generate_report", END)

    return graph.compile()


async def run_orchestrator_forever() -> None:
    cfg = load_config()
    setup_logging(level=str(cfg.get("app", "log_level", default="INFO")))

    capture_cfg = CaptureConfig(
        mode=str(cfg.get("capture", "mode", default="auto")),
        interface=str(cfg.get("capture", "interface", default="eth0")),
        bpf_filter=str(cfg.get("capture", "bpf_filter", default="ip")),
        pcap_file=str(cfg.get("capture", "pcap_file", default="") or ""),
        batch_size=int(cfg.get("capture", "batch_size", default=50)),
        batch_timeout_s=float(cfg.get("capture", "batch_timeout_s", default=1.0)),
    )

    feeds = []
    for f in (cfg.get("threat_intel", "external_feeds", default=[]) or []):
        try:
            feeds.append(
                FeedConfig(
                    name=str(f.get("name")),
                    url=str(f.get("url")),
                    type=str(f.get("type", "ip_list")),
                    refresh_minutes=int(f.get("refresh_minutes", 360)),
                )
            )
        except Exception:
            continue

    ti = ThreatIntel(
        local_db_path=str(cfg.get("threat_intel", "local_db_path", default="data/threat_intel.json")),
        feeds=feeds,
        cache_ttl_minutes=int(cfg.get("threat_intel", "cache_ttl_minutes", default=360)),
    )

    anom_cfg = AnomalyConfig(
        enabled=bool(cfg.get("ml", "anomaly", "enabled", default=True)),
        contamination=float(cfg.get("ml", "anomaly", "contamination", default=0.02)),
        model_path=str(cfg.get("ml", "anomaly", "model_path", default="data/models/anomaly_detector.joblib")),
        retrain_min_feedback=int(cfg.get("ml", "anomaly", "retrain_min_feedback", default=50)),
    )
    anomaly = AnomalyDetector(anom_cfg)
    anomaly.load_or_init()

    thresholds = SeverityThresholds(
        high=float(cfg.get("decision", "severity_thresholds", "high", default=0.85)),
        medium=float(cfg.get("decision", "severity_thresholds", "medium", default=0.60)),
    )

    response_enabled = bool(cfg.get("response", "enabled", default=True))
    dry_run = bool(cfg.get("response", "dry_run", default=True))

    alerts = AlertManager(
        telegram=TelegramConfig(
            enabled=bool(cfg.get("alerts", "telegram", "enabled", default=False)),
            bot_token=str(cfg.get("alerts", "telegram", "bot_token", default="")),
            chat_id=str(cfg.get("alerts", "telegram", "chat_id", default="")),
        ),
        slack=SlackConfig(
            enabled=bool(cfg.get("alerts", "slack", "enabled", default=False)),
            webhook_url=str(cfg.get("alerts", "slack", "webhook_url", default="")),
        ),
        email=EmailConfig(
            enabled=bool(cfg.get("alerts", "email", "enabled", default=False)),
            smtp_host=str(cfg.get("alerts", "email", "smtp_host", default="")),
            smtp_port=int(cfg.get("alerts", "email", "smtp_port", default=587)),
            username=str(cfg.get("alerts", "email", "username", default="")),
            password=str(cfg.get("alerts", "email", "password", default="")),
            to=str(cfg.get("alerts", "email", "to", default="")),
        ),
    )

    storage = Storage.from_url(cfg.database_url)
    await storage.init()

    monitoring = MonitoringAgent(capture_cfg)
    analysis = AnalysisAgent(threat_intel=ti, anomaly_detector=anomaly)
    response = ResponseAgent(dry_run=dry_run)

    app = build_security_agent_graph(
        analysis_agent=analysis,
        response_agent=response,
        thresholds=thresholds,
        response_enabled=response_enabled,
        dry_run=dry_run,
    )

    logger.info("orchestrator_started", extra={"capture_mode": capture_cfg.mode, "dry_run": dry_run})

    async for batch in monitoring.stream():
        state: SecurityState = {"network_packets": batch}
        out = await app.ainvoke(state)
        await storage.add_event("packet_batch", {"size": len(batch), "report": out.get("report", {})})
        if out.get("risk_level") in {"medium", "high"}:
            report = out.get("report", {}) or {}
            inc_id = await storage.create_incident(
                risk_level=str(out.get("risk_level")),
                max_score=float(out.get("max_score", 0.0) or 0.0),
                summary=f"{report.get('status','risk')} threats={report.get('threat_count',0)} anomalies={report.get('anomaly_count',0)}",
                report=report,
            )
            await storage.add_actions(inc_id, out.get("actions_taken", []) or out.get("actions", []) or [])
            await alerts.send(
                title=f"NSA Incident #{inc_id} ({out.get('risk_level')})",
                message=str(report.get("status", "risk")),
                extra={"max_score": out.get("max_score"), "actions": report.get("actions", [])},
            )
        # Feedback retrain can be triggered via API; here we just periodically try
        anomaly.maybe_retrain()
        logger.info("cycle_done", extra={"report": out.get("report", {}), "risk": out.get("risk_level")})


def main() -> None:
    asyncio.run(run_orchestrator_forever())


if __name__ == "__main__":
    main()


