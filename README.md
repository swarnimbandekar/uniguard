# AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

> Smart India Hackathon 2026 | NTRO Problem Statement  
> Real-time threat detection pipeline for read-only, unidirectional traffic monitoring

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        UNIDIRECTIONAL TRAFFIC FLOW                       │
│                         (Read-Only, No Return Path)                      │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │ Live Capture / PCAP / Mirrored Traffic
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  INGEST LAYER                                                           │
│  Option A: Rust PCAP Ingest — zero-copy parsing at 10,000+ pkt/s      │
│  Option B: Python Live Capture — scapy on Wi-Fi/Ethernet (Windows)     │
│  • Parses: 5-tuple, TCP flags, DNS queries, packet sizes               │
│  • Filters: multicast, broadcast, mDNS, SSDP                          │
│  • Produces JSON records to Kafka                                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Kafka: flow-records
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  FEATURE EXTRACTION + DETECTION SERVICE                                 │
│  • Aggregates packets into flows (10s windows)                         │
│  • PortScan: Local calibrated model (LogisticRegression, 18 features)  │
│    └─ Approximates Zeek conn_state from TCP flags                      │
│    └─ StreamingWindower (10s window, 2s stride, bounded memory)        │
│  • DGA: gRPC call to inference server                                  │
│  • DDoS: STANDBY (model pending retraining)                           │
└───────────────┬───────────────────────────────────┬────────────────────┘
                │ gRPC (DGA Inference)              │ Kafka: threat-alerts
                ▼                                    ▼
┌──────────────────────────────────┐  ┌─────────────────────────────────┐
│  ML INFERENCE SERVER (gRPC)      │  │  FASTAPI BACKEND                │
│  • DGA: GradientBoosting +       │  │  • Consumes alerts from Kafka   │
│         char n-grams             │  │  • WebSocket real-time push     │
│  • DDoS: STANDBY                 │  │  • REST API for history/stats   │
│  • Batch inference: <50ms        │  └───────────────┬─────────────────┘
└──────────────────────────────────┘                  │ WebSocket
                                                      ▼
                                      ┌─────────────────────────────────┐
                                      │  REACT SOC DASHBOARD            │
                                      │  • Real-time alert feed         │
                                      │  • Threat timeline (stacked)    │
                                      │  • Severity distribution        │
                                      │  • Top attacker IPs             │
                                      │  • Module status panel          │
                                      │  • Alert detail drill-down      │
                                      └─────────────────────────────────┘
```

## Detection Modules

| Module | Status | Model | Method |
|--------|--------|-------|--------|
| **Recon / Port Scan** | ACTIVE | Calibrated Logistic Regression (18 features) | Streaming windows over approximated Zeek conn_state |
| **DGA & DNS Tunnel** | ACTIVE | Gradient Boosting + char n-grams (2,3) | Statistical + n-gram features on SLD |
| **Volumetric DDoS** | STANDBY | Pending retraining | — |
| **C2 Beaconing** | STAGED | IAT periodicity analysis | — |
| **Encrypted Malware** | STAGED | JA4 + TLS metadata | — |
| **Data Exfiltration** | STAGED | Byte-ratio anomaly | — |

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.11+ (for live capture and testing)
- Npcap (Windows, for live network capture)

### 1. Start the Pipeline

```bash
docker compose up --build -d
```

This starts: Kafka, ML Inference Server, Feature Extractor, Backend, Dashboard.

### 2. Start Live Capture (separate terminal, as Admin)

```powershell
pip install scapy confluent-kafka
python scripts/live_capture.py --interface "Wi-Fi"
```

### 3. Access Dashboard

Open http://localhost:3000

### 4. Test Detection

**DGA Detection:**
```powershell
nslookup xk7v9m2qp3w8z1n4h6.com
nslookup r4tbra6jui16ubm.org
```

**Port Scan Detection:**
```powershell
nmap -sS -T4 -p 1-1000 <target-ip>
```

**DGA Model Test (standalone, no capture needed):**
```powershell
python scripts/test_dga.py
python scripts/test_dga.py --attack-only   # Push alerts to dashboard
```

**Inject All Attack Types (no capture needed):**
```powershell
python scripts/inject_live_test.py
```

## Project Structure

```
sih/
├── docker-compose.yml              # Full pipeline orchestration
├── ingest/                         # Rust PCAP ingest service
│   ├── Cargo.toml
│   ├── Dockerfile
│   └── src/main.rs
├── ml-service/                     # Python ML pipeline
│   ├── feature_extractor.py        # Kafka consumer + detection (PortScan local, DGA via gRPC)
│   ├── inference_server.py         # gRPC inference server (DGA active, DDoS standby)
│   ├── models/                     # Trained model artifacts
│   │   ├── portscan-10s2s.joblib   # Calibrated portscan model
│   │   ├── dga_gb.pkl              # DGA gradient boosting
│   │   ├── dga_vectorizer.pkl      # DGA n-gram vectorizer
│   │   └── dga_features.pkl        # DGA feature names
│   ├── portscan/                   # Port scan detection module
│   │   ├── features.py             # Window features (18 behavioral metrics)
│   │   ├── streaming.py            # Bounded-memory streaming windower
│   │   ├── model.py                # Model loading, scoring, artifact persistence
│   │   ├── alert.py                # Alert schema and severity
│   │   └── sources.py              # Zeek/TShark flow adapters
│   ├── predict_portscan.py         # Standalone portscan CLI
│   ├── retrain_dga.py              # DGA model retraining script
│   ├── train.py                    # Legacy training script (reference)
│   ├── proto/                      # gRPC protobuf definitions
│   ├── Dockerfile.extractor
│   ├── Dockerfile.inference
│   └── requirements.txt
├── backend/                        # FastAPI WebSocket backend
│   ├── main.py
│   └── Dockerfile
├── dashboard/                      # React + TypeScript SOC dashboard
│   ├── src/App.tsx
│   └── Dockerfile
├── proto/                          # Shared protobuf definitions
│   └── inference.proto
├── scripts/                        # Testing and utility scripts
│   ├── live_capture.py             # Live network capture → Kafka
│   ├── live_portscan.py            # Standalone portscan (Zeek-based)
│   ├── test_dga.py                 # DGA model evaluation + Kafka push
│   ├── inject_live_test.py         # Inject synthetic alerts
│   ├── generate_traffic.py         # Generate test PCAPs
│   └── integration_test.py         # Full pipeline integration test
├── data/
│   ├── pcaps/                      # Test PCAP files
│   └── examples/                   # Sample log files
├── ARCHITECTURE.md
├── Makefile
└── README.md
```

## Architectural Constraints

| Constraint | Implementation |
|---|---|
| **Read-only ingest** | Passive capture only; no write-back to network |
| **No payload decryption** | All analysis on metadata: IP headers, TCP flags, DNS queries |
| **Streaming, not batch** | 10-second windows with bounded latency (<15s end-to-end) |
| **Throughput target** | 10,000+ flows/sec (Rust ingest), 3000+ pkt/s (Python live capture) |
| **Standardized alerts** | JSON schema: timestamp, flow_id, threat_class, confidence, severity, evidence |
| **Bounded memory** | StreamingWindower caps per-source buffers and tracks evictions |

## Alert Schema

```json
{
  "alert_id": "uuid-v4",
  "timestamp": 1724625000.123,
  "threat_class": "PortScan",
  "confidence": 0.96,
  "severity": "CRITICAL",
  "src_ip": "67.43.228.66",
  "dst_ip": "multiple",
  "src_port": 0,
  "dst_port": 0,
  "flow_id": "67.43.228.66:0-multiple:0",
  "evidence": {
    "unique_dst_ports": 341,
    "unique_dst_hosts": 72,
    "connection_attempts": 580,
    "failed_connections": 510,
    "scan_rate": 32.1
  },
  "model_version": "portscan-10s2s"
}
```

## Performance

| Metric | Value |
|---|---|
| Ingest throughput | 10,000+ pkt/s (Rust) / 3,000+ pkt/s (Python live) |
| Feature extraction window | 10 seconds (tumbling) |
| PortScan window | 10s window, 2s stride (streaming) |
| ML inference latency | <10ms single, <50ms batch |
| End-to-end latency | <15 seconds (packet to dashboard) |
| PortScan detection | Calibrated, threshold 0.60 |
| DGA detection F1 | >0.98 (retrained on real + synthetic domains) |

## Tech Stack

- **Ingest**: Rust (pcap, etherparse, rdkafka) / Python (scapy)
- **Streaming**: Apache Kafka (KRaft mode, no Zookeeper)
- **ML**: scikit-learn (Logistic Regression, Gradient Boosting)
- **PortScan Module**: Custom streaming windower with Zeek conn_state approximation
- **Communication**: gRPC (protobuf) + Kafka
- **Backend**: FastAPI + WebSocket
- **Frontend**: React 18 + TypeScript + Recharts
- **Deployment**: Docker Compose

## Team

Smart India Hackathon 2026  
Organization: National Technical Research Organisation (NTRO)  
Theme: Blockchain & Cybersecurity
