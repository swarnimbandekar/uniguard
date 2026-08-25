# Architecture Document

## System Overview

This system implements an AI/ML pipeline for detecting cyber threats in unidirectional IP traffic. It operates under the strict constraint that the monitoring enclave has no return path to the production network — all analysis is passive, read-only, and metadata-driven.

## Components

### 1. Rust Ingest Service (`/ingest`)

**Purpose**: High-performance packet capture reader and flow record producer.

**Technology**: Rust with `pcap`, `etherparse`, and `rdkafka` crates.

**Responsibilities**:
- Read PCAP/PCAPNG files from a mounted volume (simulating a hardware data diode tap)
- Parse Ethernet → IP → TCP/UDP headers using zero-copy parsing
- Extract per-packet metadata: 5-tuple, TCP flags, payload length, timestamps
- Parse DNS queries from UDP port 53 payloads
- Serialize records as JSON and produce to Kafka `flow-records` topic
- Support configurable replay speeds (real-time, 2x, 10x, max)
- Report throughput metrics to stdout

**Key Design Decisions**:
- Zero-copy packet parsing via `etherparse` for minimal allocation overhead
- Async Kafka production with batching (`linger.ms=5`, `batch.num.messages=1000`)
- No payload inspection beyond protocol headers (enforces no-decryption constraint)
- File-watching capability for continuous PCAP ingestion

**Performance**: 10,000+ packets/second single-threaded on commodity hardware.

---

### 2. Feature Extraction Service (`/ml-service/feature_extractor.py`)

**Purpose**: Aggregate raw packet records into flow-level features and route to ML inference.

**Technology**: Python with `confluent-kafka` and `grpc`.

**Responsibilities**:
- Consume JSON packet records from Kafka `flow-records` topic
- Maintain in-memory flow table keyed by 5-tuple (bidirectional)
- Compute per-flow statistics over configurable time windows (default 10s):
  - Duration, packet counts, byte counts
  - Inter-arrival time statistics (mean, std, max, min)
  - TCP flag counts (SYN, ACK, RST, FIN, PSH)
  - Byte rate and packet rate
- Compute per-source-IP fan-out features for port scan detection:
  - Unique destination ports and IPs
  - Port entropy
  - SYN ratio
- Extract DNS domain features for DGA detection:
  - Shannon entropy
  - Character distribution ratios
  - Consonant run length
- Call gRPC inference server with batch requests
- Produce structured alerts to Kafka `threat-alerts` topic

**Windowing Strategy**: Fixed 10-second tumbling windows. At window close, all accumulated flows are finalized and sent for inference. This provides bounded latency (<15s end-to-end).

---

### 3. ML Inference Server (`/ml-service/inference_server.py`)

**Purpose**: Serve pre-trained threat detection models via gRPC.

**Technology**: Python with `grpc`, `scikit-learn`, `joblib`.

**Models**:

| Model | Algorithm | Input | Output |
|-------|-----------|-------|--------|
| DDoS | Random Forest (100 trees, depth 20) | 22 flow-level features | Binary: BENIGN/DDoS |
| PortScan | Gradient Boosting (200 trees, depth 5) | 9 fan-out features (scaled) | Binary: BENIGN/PortScan |
| DGA | Gradient Boosting (300 trees, depth 6) | 10 stat features + 300 n-gram features | Binary: BENIGN/DGA |

**API**:
- `PredictFlow(FlowFeatures, detection_type)` → single prediction
- `PredictFlowBatch(FlowFeatures[], detection_type)` → batch prediction
- `PredictDns(DnsFeatures)` → single DGA prediction
- `PredictDnsBatch(DnsFeatures[])` → batch DGA prediction
- `HealthCheck()` → server status and loaded models

**Severity Mapping**:
- Confidence ≥ 0.95 → CRITICAL
- Confidence ≥ 0.90 → HIGH
- Confidence ≥ 0.80 → MEDIUM
- Confidence < 0.80 → LOW (not alerted)

---

### 4. FastAPI Backend (`/backend/main.py`)

**Purpose**: Bridge between Kafka alerts and the React dashboard via WebSocket and REST.

**Technology**: Python with FastAPI, uvicorn, WebSocket.

**Endpoints**:
- `GET /api/health` — Service health and uptime
- `GET /api/stats` — Aggregate alert statistics
- `GET /api/alerts?page=1&page_size=50` — Paginated alert history
- `GET /api/alerts/recent?limit=20` — Most recent alerts
- `GET /api/alerts/timeline?window_minutes=5` — Time-bucketed alert counts
- `WS /ws/alerts` — Real-time alert stream

**Design**:
- Background thread consumes from Kafka `threat-alerts`
- In-memory deque stores last 10,000 alerts (sufficient for prototype)
- All connected WebSocket clients receive each alert immediately
- Auto-reconnect support via heartbeat messages

---

### 5. React Dashboard (`/dashboard`)

**Purpose**: Real-time visualization of threat detections.

**Technology**: React 18 + TypeScript, Recharts, Vite.

**Components**:
- **Stats Cards**: Total alerts, alerts/min, critical threats, active sources
- **Alert Timeline**: Line chart showing alert rate by threat type (30-point sliding window)
- **Alert Feed**: Real-time scrolling list, color-coded by severity
- **Threat Distribution**: Donut chart of alert counts by class
- **Top Attackers**: Horizontal bar chart of source IPs
- **Detail Panel**: Slide-in panel showing full alert evidence on click

**Design Decisions**:
- Dark theme (standard for security operations centers)
- WebSocket with auto-reconnect (3s retry)
- Client-side state only — no client-side persistence
- Responsive CSS Grid layout

---

### 6. Messaging Infrastructure (Kafka)

**Configuration**: Apache Kafka 3.7 in KRaft mode (no Zookeeper dependency).

**Topics**:
| Topic | Partitions | Purpose |
|-------|-----------|---------|
| `flow-records` | 4 | Raw packet records from ingest |
| `flow-features` | 4 | (Reserved) Computed features |
| `threat-alerts` | 2 | Classified threat alerts |

**Retention**: 1 hour (sufficient for live monitoring; not a storage system).

---

## Data Flow

```
PCAP File → [Rust Ingest] → Kafka:flow-records → [Feature Extractor] → gRPC → [ML Inference]
                                                         ↓
                                                  Kafka:threat-alerts
                                                         ↓
                                                  [FastAPI Backend]
                                                         ↓
                                                  WebSocket → [React Dashboard]
```

## Security Model

1. **Read-Only Ingest**: The Rust service reads from a mounted volume. No network write-back.
2. **No Decryption**: TLS traffic analyzed by metadata only (future: JA3/JA4 fingerprints).
3. **Isolation**: Each service runs in its own container with minimal privileges.
4. **No Inline Blocking**: The system produces intelligence (alerts), never mitigation commands.

## Deployment

Single-machine deployment via Docker Compose. All services communicate over a private Docker bridge network (`threatnet`). External access only via:
- Port 3000: Dashboard (nginx)
- Port 8000: API (for debugging/testing)

For production, services would be distributed across multiple hosts with Kafka cluster replication.

## Scalability Considerations

- **Horizontal Ingest**: Multiple Rust instances can read different PCAP files
- **Kafka Partitioning**: 4 partitions allow up to 4 parallel feature extractor instances
- **Inference Scaling**: gRPC server can run multiple replicas behind a load balancer
- **Model Updates**: Hot-reload models by mounting a new model directory (no restart needed — future enhancement)
