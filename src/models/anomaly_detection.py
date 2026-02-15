from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


logger = logging.getLogger(__name__)


def _pkt_to_features(pkt: Dict[str, Any]) -> List[float]:
    # Keep features simple & robust across capture modes
    src_port = float(pkt.get("src_port") or 0)
    dst_port = float(pkt.get("dst_port") or 0)
    proto = float(pkt.get("proto") or 0)
    length = float(pkt.get("len") or 0)
    l4 = str(pkt.get("l4") or "")
    l4_id = 1.0 if l4 == "tcp" else (2.0 if l4 == "udp" else 0.0)
    return [src_port, dst_port, proto, length, l4_id]


@dataclass
class AnomalyConfig:
    enabled: bool = True
    contamination: float = 0.02
    model_path: str = "data/models/anomaly_detector.joblib"
    retrain_min_feedback: int = 50


class AnomalyDetector:
    def __init__(self, cfg: AnomalyConfig):
        self.cfg = cfg
        self.model_path = Path(cfg.model_path)
        self.model: Optional[IsolationForest] = None
        self._feedback_X: List[List[float]] = []
        self._feedback_y: List[int] = []  # 0 normal, 1 anomalous

    def load_or_init(self) -> None:
        if not self.cfg.enabled:
            return
        try:
            if self.model_path.exists():
                self.model = joblib.load(self.model_path)
                return
        except Exception as e:
            logger.warning("anomaly_model_load_failed", extra={"err": str(e)})
        self.model = IsolationForest(
            n_estimators=200,
            contamination=float(self.cfg.contamination),
            random_state=42,
        )
        # cold start: fit on a tiny synthetic baseline
        X0 = np.array(
            [
                [12000, 80, 6, 400, 1],
                [13000, 443, 6, 500, 1],
                [14000, 53, 17, 200, 2],
            ],
            dtype=float,
        )
        self.model.fit(X0)

    def score_packets(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.cfg.enabled:
            return []
        if self.model is None:
            self.load_or_init()
        assert self.model is not None

        X = np.array([_pkt_to_features(p) for p in packets], dtype=float)
        # IsolationForest: higher = more normal; we invert to anomaly score in 0..1
        raw = self.model.score_samples(X)  # typically negative values
        # normalize with robust min/max per batch
        mn, mx = float(np.min(raw)), float(np.max(raw))
        denom = (mx - mn) if (mx - mn) > 1e-9 else 1.0
        norm = (raw - mn) / denom
        anomaly_score = 1.0 - norm

        out: List[Dict[str, Any]] = []
        for pkt, s in zip(packets, anomaly_score.tolist()):
            if s >= 0.7:
                out.append(
                    {
                        "score": float(s),
                        "src_ip": pkt.get("src_ip"),
                        "dst_ip": pkt.get("dst_ip"),
                        "dst_port": pkt.get("dst_port"),
                        "features": _pkt_to_features(pkt),
                    }
                )
        return out

    def add_feedback(self, packet_like: Dict[str, Any], label: int) -> None:
        """
        label: 0 normal, 1 anomalous
        """
        self._feedback_X.append(_pkt_to_features(packet_like))
        self._feedback_y.append(int(label))

    def maybe_retrain(self) -> Tuple[bool, str]:
        """
        Lightweight feedback loop: retrain IsolationForest primarily on "normal" labeled samples.
        """
        if not self.cfg.enabled:
            return False, "disabled"
        if len(self._feedback_X) < int(self.cfg.retrain_min_feedback):
            return False, "insufficient_feedback"

        if self.model is None:
            self.load_or_init()
        assert self.model is not None

        X = np.array(self._feedback_X, dtype=float)
        y = np.array(self._feedback_y, dtype=int)
        X_normal = X[y == 0]
        if len(X_normal) < 10:
            return False, "not_enough_normal_samples"

        self.model.fit(X_normal)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        self._feedback_X.clear()
        self._feedback_y.clear()
        return True, "retrained"






