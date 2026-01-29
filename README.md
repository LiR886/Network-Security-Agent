## Network Security AI Agent (LangGraph)

Production-ready starter for an autonomous network security agent:

- **LangGraph** multi-agent pipeline with state + branching
- **Async packet capture** (Scapy when available; safe fallback when raw capture is not permitted)
- **ML anomaly detection** (IsolationForest) + feedback loop to improve model
- **Threat intelligence**: local DB + external feeds refresh
- **FastAPI** REST API + simple Web UI dashboard (polling)
- **Storage**: SQLite default, Postgres via Docker
- **Docker Compose**: `agent` + `api` + `db`

### Quick start (Docker)

1) Update secrets in `config.yaml` (at least `app.api_key`).
2) Run:

```bash
cd network_security_agent
docker compose up --build
```

Services:
- **API**: `http://localhost:8000` (Dashboard at `/ui`, OpenAPI at `/docs`)
- **Agent**: background orchestrator consuming packets and creating incidents
- **DB**: Postgres (optional) + persistent volume

### Optional: enable real packet sniffing in Docker

By default the agent uses safe fallback capture when raw sockets are not available.
If you want real sniffing with Scapy, you typically need extra capabilities:

- set `capture.mode: scapy` in `config.yaml`
- add `cap_add: ["NET_RAW"]` (and possibly `NET_ADMIN`) to the `agent` service

### Local run (without Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export NSA_CONFIG=./config.yaml
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

In another terminal:

```bash
python -m src.agents.orchestrator
```

### Security notes

- Real packet sniffing may require `CAP_NET_RAW` and root or container capabilities. The project supports **safe fallback** mode (mock packets) for environments without privileges.
- Response actions run in **dry-run** by default (see `config.yaml`).
- SIEM endpoints require `X-API-Key: <app.api_key>`.

### Key endpoints (SIEM integration)

- `POST /siem/events`: push external events into the system
- `GET /incidents`: list incidents
- `POST /feedback`: label events/anomalies to improve ML model
- `GET /healthz`: health check

### Project layout

See `network_security_agent/` tree in the repo. Main graph is built in:
- `src/agents/orchestrator.py`


