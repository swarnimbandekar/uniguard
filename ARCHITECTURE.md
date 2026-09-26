# UniGuard architecture

## Purpose

UniGuard is a metadata-only cyber-threat detection pipeline for traffic observed on a one-way monitoring path. It does not send traffic back to the monitored network, decrypt payloads, or inspect application content. Its inputs are packet headers, lengths, TCP flags, timing, and DNS query names when present.

Two alternative sources feed the same pipeline:

- **PCAP replay:** the Rust `ingest` service reads `.pcap`, `.pcapng`, and `.cap` files from `data/pcaps`.
- **Live Windows capture:** `scripts/live_capture.py` uses Scapy/Npcap on the host and publishes passive captures to Kafka.

Both publish packet-record JSON to `flow-records`.

## Runtime topology

```text
PCAP files ──> Rust ingest ─┐
                            ├─> Kafka: flow-records ─> Feature extractor
Live interface ─> Scapy ────┘                              │
                                      ┌─────────────────────┴───────────────────┐
                                      │ local detectors                         │ gRPC
                                      v                                         v
                             Kafka: threat-alerts                    DGA inference server
                                      │
                                      v
                               FastAPI backend
                                      │ REST + WebSocket
                                      v
                         React dashboard / Windows launcher
```

`docker-compose.yml` starts Kafka, topic initialization, PCAP ingest, ML inference, feature extraction, backend, dashboard, and a Cloudflare tunnel. The tunnel is not needed for local operation.

## Components

| Component | Entry point | Responsibility | Interface |
|---|---|---|---|
| Kafka | Compose `kafka` and `kafka-init` | Event transport and topic creation | `9092` host / `29092` Compose network |
| PCAP ingest | `ingest/src/main.rs` | Parses Ethernet/IP/TCP/UDP captures, extracts DNS queries where possible, publishes packet records | produces `flow-records` |
| Live capture | `scripts/live_capture.py` | Native Windows passive capture; filters common multicast/broadcast and local DNS noise | produces `flow-records` |
| Feature extractor | `ml-service/feature_extractor.py` | Aggregates flow state, scores detectors, and emits alerts | consumes `flow-records`, produces `threat-alerts`, calls gRPC |
| Inference server | `ml-service/inference_server.py` | Loads DGA artifacts and provides protobuf inference/health RPCs | gRPC `50051` |
| Backend | `backend/main.py` | Keeps recent alerts in memory, calculates stats, serves REST and WebSocket clients | `8000` container / `8001` host |
| Dashboard | `dashboard/` | React SOC dashboard; REST bootstrap plus WebSocket updates | Nginx `80` container / `3000` host |
| Launcher | `launcher/app.py` | Windows Tkinter control panel for Compose, health, demos, capture, and dashboard summary | host-side Docker/HTTP control |

## Kafka contracts

| Topic | Partitions | Producer | Consumer | Status |
|---|---:|---|---|---|
| `flow-records` | 4 | PCAP ingest or live capture | feature extractor | active |
| `threat-alerts` | 2 | feature extractor | backend | active |
| `flow-features` | 4 | — | — | created for future use |

A packet record includes endpoint addresses and ports, protocol, microsecond timestamp, packet/payload lengths, TCP flags where applicable, an optional DNS query, and ingest time.

An alert includes a UUID, timestamp, threat class, confidence, severity, endpoints, derived `flow_id`, detector-specific `evidence`, and model version.

## Detection flow

The feature extractor consumes records in a Kafka consumer group and resets primary flow state every `WINDOW_SECONDS` (10 seconds by default). It flushes alerts at each boundary. C2 connection history persists across windows to measure periodicity over longer intervals.

| Threat class | Primary execution location | Method |
|---|---|---|
| `PortScan` | feature extractor | Calibrated model with streaming windows and connection-state approximation |
| `DDoS` | feature extractor | Per-destination aggregation, local flow model, and behavioral guards |
| `EncryptedMalware` | feature extractor | Local flow-metadata model for suspicious non-standard-port behavior |
| `DataExfiltration` | feature extractor | Local flow-metadata model plus asymmetric-upload logic |
| `C2_BEACONING` | feature extractor | Stateful periodicity/jitter analysis; excludes endpoints claimed by scan/flood logic in the same window |
| `DGA` | inference server | Gradient boosting over domain statistics and character n-grams |

The extractor retains a legacy DDoS gRPC request path, but its active DDoS alert path is the local per-destination scorer. The inference service currently loads DGA artifacts; other RPC branches are compatibility paths, not the primary detector implementation.

## Backend and client flow

The dashboard requests `/api/stats` and `/api/alerts` for initial state, then connects to `/ws/alerts`. Nginx proxies API and WebSocket traffic to the backend in Compose; Vite proxies the same paths during local frontend development.

The backend keeps at most 10,000 alerts in an in-memory `deque`. Restarting it clears the alert history and statistics; Kafka is transport, not long-term alert storage.

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Status, uptime, alert count, WebSocket count |
| `GET /api/stats` | Aggregate counts, rate, source ranking |
| `GET /api/alerts` | Paginated alerts with threat/severity filters |
| `GET /api/alerts/recent` | Latest alerts |
| `POST /api/alerts/clear` | Clears in-memory alerts and stats |
| `GET /api/alerts/timeline` | Ten-second alert buckets |
| `POST /api/demo`, `GET /api/demo/status` | Demo execution and status |
| `WS /ws/alerts` | Recent replay, live alert events, and keepalives |

## Deployment configuration

Compose uses the `threatnet` bridge network. Host-facing ports are Kafka `9092`, gRPC `50051`, backend `8001`, and dashboard `3000`. Services use internal names including `kafka:29092`, `ml-inference:50051`, and `backend:8000`.

| Setting | Compose value | Consumer |
|---|---|---|
| `KAFKA_BROKER` | `kafka:29092` | ingest, extractor, backend |
| `KAFKA_INPUT_TOPIC` | `flow-records` | extractor |
| `KAFKA_OUTPUT_TOPIC` / `KAFKA_TOPIC` | `threat-alerts` | extractor / backend |
| `WINDOW_SECONDS` | `10` | extractor |
| `CONFIDENCE_THRESHOLD` | `0.8` | extractor gRPC-result filtering |
| detector model path variables | `/app/models/*` | extractor |
| `GRPC_INFERENCE_HOST` | `ml-inference:50051` | extractor |

Model artifacts and the PCAP input directory are mounted read-only. Live capture remains outside Docker on Windows because it requires host interface access.

## Repository map

```text
backend/                 FastAPI alert service
dashboard/               React dashboard and Nginx proxy
ingest/                  Rust offline-PCAP replay producer
launcher/                Windows Tkinter console and PyInstaller setup
ml-service/              extractor, inference service, detector packages, models, training
proto/                   inference protobuf contract
scripts/                 capture, injection, attack, test, and troubleshooting utilities
c2_beaconing_detector/   reference/legacy C2 package
docker-compose.yml       local multi-service topology
```

`proto/inference.proto` and `ml-service/proto/inference.proto` are duplicate protobuf definitions used by the ML Docker builds; update both when changing the RPC contract.

## Operational limitations

- UniGuard monitors only; it does not block or remediate traffic.
- Detection quality depends on capture visibility, model calibration, and local traffic characteristics.
- Windowing adds a normal delay before an event can become eligible for alerting.
- Add an external storage sink before using alerts for retention or audit requirements.
