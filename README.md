# UniGuard

> Smart India Hackathon 2026 · NTRO problem statement

UniGuard is a real-time, metadata-only cyber-threat detection pipeline for passively observed, unidirectional IP traffic. It accepts replayed PCAP files or a native Windows capture bridge, detects six threat classes, and presents alerts in a live SOC dashboard.

It does not decrypt payloads, send traffic back to the monitored network, block connections, or preserve alert history after the backend restarts.

## Detection coverage

| Threat | Where it runs | Approach |
|---|---|---|
| Port scanning | Feature extractor | Calibrated streaming port-scan model |
| DDoS | Feature extractor | Per-destination aggregation and a flow-metadata model |
| DGA | gRPC inference server | Domain statistics and character n-grams |
| C2 beaconing | Feature extractor | Stateful periodicity and jitter analysis |
| Encrypted malware | Feature extractor | Flow-metadata model for non-standard-port traffic |
| Data exfiltration | Feature extractor | Flow-metadata model with asymmetric-upload checks |

The primary detection window is 10 seconds by default. C2 timing state carries across windows so repeated connections can be evaluated over longer periods.

## Pipeline

```text
PCAP replay (Rust) ─┐
                    ├─> Kafka: flow-records ─> Feature extractor ─> Kafka: threat-alerts
Live capture (Scapy)┘                                  │                        │
                                                       gRPC                     v
                                                        │                  FastAPI backend
                                                        v                        │
                                                  DGA inference service    REST + WebSocket
                                                                                 │
                                                                          React dashboard
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full service map, event contracts, API routes, deployment settings, and implementation notes.

## Quick start

### Prerequisites

- Docker Desktop with Docker Compose
- Python 3.11+ for host-side scripts and the launcher
- Npcap and an elevated terminal for live capture on Windows
- Explicit authorization before using the live-attack helper against any target

### Windows desktop console

The launcher can control Compose, show service health, open the dashboard summary, and start the native capture bridge.

```powershell
python launcher/app.py
```

Build the standalone executable with:

```powershell
powershell -ExecutionPolicy Bypass -File launcher/build.ps1
```

See [launcher/README.md](launcher/README.md) for launcher details.

### Command line

From the repository root:

```bash
docker compose up --build -d
```

This starts Kafka, topic initialization, PCAP ingest, ML inference, the feature extractor, backend, dashboard, and the configured Cloudflare tunnel. The PCAP ingest service waits when `data/pcaps` is empty.

Open <http://localhost:3000>. Check the API at <http://localhost:8001/api/health>.

```bash
docker compose ps
docker compose logs -f feature-extractor
docker compose down
```

## Choose an input source

### PCAP replay

Place `.pcap`, `.pcapng`, or `.cap` files in `data/pcaps/` before starting the stack. The Rust ingest service mounts that directory read-only and publishes normalized packet records to Kafka. Its `REPLAY_SPEED` is configured in `docker-compose.yml`.

### Native live capture (Windows)

The live bridge runs outside Docker because it requires host network-interface access.

```powershell
python scripts/list_interfaces.py
python scripts/live_capture.py --interface "Ethernet 2" --target 192.168.56.101
```

Run it in an elevated terminal after Kafka is available. It publishes to `localhost:9092`, filters common multicast/broadcast traffic and local-service DNS noise, and sends packet metadata to the pipeline.

## Demos and testing

For a no-capture smoke demo, publish bundled synthetic scenarios directly to Kafka:

```powershell
python scripts/inject_all_threats.py
```

The current injector sends four synthetic patterns: DDoS, DGA queries, repeated non-standard-port traffic, and asymmetric upload traffic. Based on the loaded models and guards, the repeated pattern may exercise C2 and/or encrypted-malware logic. It is not a deterministic complete demonstration of every detector.

For an authorized lab environment, start the capture bridge and run:

```powershell
python scripts/attack_metasploitable.py
```

Use one detector-specific option when needed: `--only portscan`, `ddos`, `exfil`, `c2`, `encmal`, or `dga`. Do not use this helper against systems or networks without explicit permission.

Clear the in-memory dashboard state between runs:

```powershell
Invoke-RestMethod -Method POST -Uri "http://localhost:8001/api/alerts/clear"
```

## API

| Endpoint | Use |
|---|---|
| `GET /api/health` | Service status and alert count |
| `GET /api/stats` | Aggregate alert metrics |
| `GET /api/alerts` | Filterable, paginated alerts |
| `POST /api/alerts/clear` | Clear in-memory alerts and statistics |
| `WS /ws/alerts` | Real-time alert feed |

Compose maps the HTTP API to `http://localhost:8001`; the dashboard proxies `/api` and `/ws` internally.

## Repository layout

```text
backend/                 FastAPI API and Kafka alert consumer
dashboard/               React SOC interface
ingest/                  Rust PCAP replay producer
launcher/                Windows desktop control console
ml-service/              detectors, extractor, gRPC service, models, training scripts
proto/                   shared inference protobuf contract
scripts/                 capture, injection, lab, and test helpers
c2_beaconing_detector/   reference/legacy C2 package
docker-compose.yml       local deployment topology
```

## Limitations

- The backend retains at most 10,000 alerts in memory; restarting it clears the dashboard history. Use an external storage sink for retention.
- Compose is a local development topology, not a production HA or security-hardened deployment.
- Model artifacts are under `ml-service/models`; retraining and validation are separate operational tasks.
- Treat detections as analyst signals: quality depends on capture visibility, calibration, and the monitored environment.

## Model performance

| Model | ROC-AUC | F1 | FPR | Threshold | Throughput |
|---|---|---|---|---|---|
| DDoS | 0.92 | 0.85 | 0.000 | 0.92 | 95,504 flows/s |
| Encrypted Malware | 0.87 | 0.8646 | 0.000 | 0.28 | 42,045 flows/s |
| Data Exfiltration | 0.94 | 0.8999 | 5e-5 | 0.96 | 76,863 flows/s |
| DGA | — | >0.98 | — | — | gRPC batch |
| Port Scan | — | calibrated | — | 0.60 | streaming |

> Flow-model metrics are on held-out synthetic validation data; production behavior is
> further constrained by rule overrides and minimum-volume guards to suppress false
> positives on real traffic.

## Technology

| Layer | Technology |
|---|---|
| Capture and replay | Rust (`pcap`, `etherparse`, `rdkafka`) and Python/Scapy |
| Event streaming | Apache Kafka in KRaft mode |
| Detection and inference | Python, scikit-learn, NumPy, joblib, gRPC |
| Backend | FastAPI, Uvicorn, Confluent Kafka, WebSockets |
| Dashboard | React, TypeScript, Vite, Recharts, Nginx |
| Operations | Docker Compose; Windows Tkinter launcher packaged with PyInstaller |
