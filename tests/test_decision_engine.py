from src.core.decision_engine import SeverityThresholds, decide_actions, severity_from_score


def test_severity_from_score():
    t = SeverityThresholds(high=0.85, medium=0.6)
    assert severity_from_score(0.1, t) == "low"
    assert severity_from_score(0.6, t) == "medium"
    assert severity_from_score(0.99, t) == "high"


def test_decide_actions_blocks_ip_for_high():
    threats = [{"severity": "high", "dst_ip": "1.2.3.4"}]
    actions = decide_actions(threats=threats, anomalies=[], enabled=True, dry_run=True)
    assert any(a["type"] == "block_ip" and a["ip"] == "1.2.3.4" for a in actions)






