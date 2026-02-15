from src.models.anomaly_detection import AnomalyConfig, AnomalyDetector


def test_anomaly_feedback_retrain(tmp_path):
    cfg = AnomalyConfig(enabled=True, contamination=0.02, model_path=str(tmp_path / "m.joblib"), retrain_min_feedback=10)
    det = AnomalyDetector(cfg)
    det.load_or_init()

    # provide "normal" feedback
    pkt = {"src_port": 12000, "dst_port": 80, "proto": 6, "len": 500, "l4": "tcp"}
    for _ in range(12):
        det.add_feedback(pkt, 0)

    retrained, reason = det.maybe_retrain()
    assert retrained is True
    assert reason == "retrained"





