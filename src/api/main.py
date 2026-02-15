from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..core.storage import Storage
from ..models.anomaly_detection import AnomalyConfig, AnomalyDetector
from ..utils.config import load_config
from ..utils.logger import setup_logging
from .endpoints import AppDeps, router


logger = logging.getLogger(__name__)


BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


def create_app() -> FastAPI:
    cfg = load_config()
    setup_logging(level=str(cfg.get("app", "log_level", default="INFO")))

    app = FastAPI(title="Network Security Agent API", version="0.1.0")

    storage = Storage.from_url(cfg.database_url)

    anom_cfg = AnomalyConfig(
        enabled=bool(cfg.get("ml", "anomaly", "enabled", default=True)),
        contamination=float(cfg.get("ml", "anomaly", "contamination", default=0.02)),
        model_path=str(cfg.get("ml", "anomaly", "model_path", default="data/models/anomaly_detector.joblib")),
        retrain_min_feedback=int(cfg.get("ml", "anomaly", "retrain_min_feedback", default=50)),
    )
    anomaly = AnomalyDetector(anom_cfg)
    anomaly.load_or_init()

    app.state.deps = AppDeps(storage=storage, anomaly=anomaly)

    @app.on_event("startup")
    async def _startup() -> None:
        await storage.init()
        logger.info("api_started")

    # UI
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/ui", response_class=HTMLResponse)
    async def ui(request: Request):
        return templates.TemplateResponse("dashboard.html", {"request": request})

    app.include_router(router)
    return app


app = create_app()






