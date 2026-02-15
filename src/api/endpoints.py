from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.storage import Storage
from ..models.anomaly_detection import AnomalyConfig, AnomalyDetector
from ..utils.config import AppConfig, load_config


router = APIRouter()


def get_cfg() -> AppConfig:
    return load_config()


def require_api_key(x_api_key: Optional[str] = Header(default=None), cfg: AppConfig = Depends(get_cfg)) -> None:
    if not x_api_key or x_api_key != cfg.api_key:
        raise HTTPException(status_code=401, detail="invalid_api_key")


@dataclass
class AppDeps:
    storage: Storage
    anomaly: AnomalyDetector


def get_deps(request: Request) -> AppDeps:
    return request.app.state.deps


class SiemEventIn(BaseModel):
    source: str = Field(default="siem")
    event_type: str = Field(default="external_event")
    severity: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


@router.get("/healthz")
async def healthz():
    return {"ok": True}


@router.get("/incidents", dependencies=[Depends(require_api_key)])
async def list_incidents(limit: int = 100, deps: AppDeps = Depends(get_deps)):
    return {"items": await deps.storage.list_incidents(limit=limit)}


@router.get("/incidents/{incident_id}", dependencies=[Depends(require_api_key)])
async def get_incident(incident_id: int, deps: AppDeps = Depends(get_deps)):
    inc = await deps.storage.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="incident_not_found")
    return inc


@router.post("/siem/events", dependencies=[Depends(require_api_key)])
async def ingest_siem_event(body: SiemEventIn, deps: AppDeps = Depends(get_deps)):
    event_id = await deps.storage.add_event(
        "siem_event",
        {"source": body.source, "event_type": body.event_type, "severity": body.severity, "payload": body.payload},
    )
    return {"event_id": event_id}


class FeedbackIn(BaseModel):
    label: int = Field(description="0 normal, 1 anomaly, 2 confirmed threat", ge=0, le=2)
    packet_like: Dict[str, Any] = Field(default_factory=dict)


@router.post("/feedback", dependencies=[Depends(require_api_key)])
async def add_feedback(body: FeedbackIn, deps: AppDeps = Depends(get_deps)):
    fb_id = await deps.storage.add_feedback(label=int(body.label), payload=body.packet_like)

    # Feed into anomaly retraining loop
    if body.label in (0, 1):
        deps.anomaly.add_feedback(body.packet_like, 1 if body.label == 1 else 0)
        retrained, reason = deps.anomaly.maybe_retrain()
    else:
        retrained, reason = False, "label_not_used_for_anomaly"

    return {"feedback_id": fb_id, "retrained": retrained, "reason": reason}


