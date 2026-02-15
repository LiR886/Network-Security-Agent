import asyncio

from src.core.threat_intelligence import ThreatIntel, FeedConfig


def test_threat_intel_local_score(tmp_path):
    db = tmp_path / "ti.json"
    db.write_text(
        """
        {"malicious_ips":[{"ip":"203.0.113.66","severity":0.95,"tags":["ssh"]}],
         "signatures":[{"name":"ssh","match":{"dst_port":22},"severity":0.7,"tag":"ssh"}]}
        """,
        encoding="utf-8",
    )
    ti = ThreatIntel(local_db_path=str(db), feeds=[], cache_ttl_minutes=0)
    asyncio.run(ti.ensure_loaded())
    score, tags, evidence = ti.score_packet({"dst_ip": "203.0.113.66", "dst_port": 22})
    assert score >= 0.7
    assert "ssh" in tags
    assert len(evidence) >= 1






