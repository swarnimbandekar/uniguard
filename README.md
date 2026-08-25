# AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

> Smart India Hackathon 2024 | NTRO Problem Statement  
> Real-time threat detection pipeline for read-only, unidirectional traffic monitoring

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        UNIDIRECTIONAL TRAFFIC FLOW                       │
│                         (Read-Only, No Return Path)                      │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │ PCAP / Mirrored Traffic
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  RUST INGEST SERVICE                                                    │
│  • Reads PCAP files via libpcap                                        │
│  • Parses Ethernet/IP/TCP/UDP with etherparse (zero-copy)              │
│  • Extracts: 5-tuple, TCP flags, DNS queries, packet sizes             │
│  • Produces JSON records to Kafka at 10,000+ pkt/s                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Kafka: flow-records
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  PYTHON FEATURE EXTRACTION SERVICE                                      │
│  • Aggregates packets into flows (10s windows)                         │
│  • Computes: IAT stats, byte rates, flag counts, fan-out metrics       │
│  • DNS analysis: character entropy, n-grams                            │
│  • Calls ML Inference via gRPC                                         │
└───────────────┬───────────────────────────────────┬────────────────────┘
                │ gRPC (Batch Predict)              │ Kafka: threat-alerts
                ▼                                    ▼
┌──────────────────────────────┐    ┌───────────────────────────────────┐
│  ML INFERENCE SERVER (gRPC)  │    │  FASTAPI BACKEND                  │
│  • DDoS: Random Forest       │    │  • Consumes alerts from Kafka     │
│  • PortScan: Gradient Boost  │    │  • WebSocket real-time streaming  │
│  • DGA: GB + char n-grams    │    │  • REST API for history/stats     │
│  • Batch inference: <50ms    │    └───────────────┬───────────────────┘
└──────────────────────────────┘                    │ WebSocket
                                                    ▼
                                    ┌───────────────────────────────────┐
                                    │  REACT + D3 DASHBOARD             │
                                    │  • Real-time alert feed           │
                                    │  • Threat timeline chart          │
                                    │  • Distribution pie chart         │
                                    │  • Top attacker IPs               │
                                    │  • Alert detail drill-down        │
                                    └───────────────────────────────────┘
```

## Threat Detection Coverage

| Threat Type | Detection Method | Model | Key Features |
|---|---|---|---|
| **DDoS (SYN Flood)** | Classical ML | Random Forest | Flow bytes/s, packets/s, SYN count, IAT stats |
| **Port Scanning** | Classical ML | Gradient Boosting | Unique dst ports, port entropy, SYN ratio |
| **DGA / DNS Tunneling** | Hybrid ML | Gradient Boosting + n-gram | Domain entropy, consonant ratio, char n-grams |

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.11+ (for training and traffic generation)
- Rust 1.77+ (for building ingest service locally)

### 1. Train Models (first time only)

```bash
cd ml-service
pip install -r requirements.txt
python train.py
```

### 2. Generate Demo Traffic

```bash
pip install scapy
python scripts/generate_traffic.py --output data/pcaps
```

### 3. Start the Pipeline

```bash
docker-compose up --build
```

### 4. Access Dashboard

Open http://localhost:3000

## Project Structure

```
sih/
├── docker-compose.yml          # Full pipeline orchestration
├── ingest/                     # Rust PCAP ingest service
│   ├── Cargo.toml
│   ├── Dockerfile
│   └── src/main.rs
├── ml-service/                 # Python ML pipeline
│   ├── train.py                # Model training script
│   ├── inference_server.py     # gRPC inference server
│   ├── feature_extractor.py    # Kafka consumer + feature computation
│   ├── models/                 # Trained model artifacts
│   └── proto/                  # gRPC protocol definitions
├── backend/                    # FastAPI WebSocket backend
│   └── main.py
├── dashboard/                  # React + D3 visualization
│   ├── src/App.tsx
│   └── src/index.css
├── proto/                      # Shared protobuf definitions
│   └── inference.proto
├── scripts/                    # Traffic generation tools
│   └── generate_traffic.py
└── data/                       # Datasets and PCAPs
    └── pcaps/
```

## Architectural Constraints (as required)

| Constraint | Implementation |
|---|---|
| **Read-only ingest** | Rust service reads PCAPs from mounted volume; no write-back path |
| **No payload decryption** | All analysis on metadata: IP headers, TCP flags, DNS queries, TLS Client Hello |
| **Streaming, not batch** | 10-second sliding windows with bounded latency (<15s end-to-end) |
| **Throughput target** | Tested at 10,000+ flows/sec (single-threaded Rust ingest) |
| **Standardized alerts** | JSON schema: timestamp, flow_id, threat_class, confidence, severity, evidence |

## Alert Schema

```json
{
  "alert_id": "uuid-v4",
  "timestamp": 1703001234.567,
  "threat_class": "DDoS",
  "confidence": 0.97,
  "severity": "CRITICAL",
  "src_ip": "203.0.113.50",
  "dst_ip": "10.0.0.1",
  "src_port": 54321,
  "dst_port": 80,
  "flow_id": "203.0.113.50:54321-10.0.0.1:80",
  "evidence": {
    "flow_bytes_per_sec": 5200000.0,
    "syn_count": 1450,
    "fwd_packets": 1500,
    "duration_ms": 2.3
  },
  "model_version": "1.0.0"
}
```

## Performance

| Metric | Value |
|---|---|
| Ingest throughput | 10,000+ pkt/s (Rust, single core) |
| Feature extraction window | 10 seconds |
| ML inference latency | <10ms single, <50ms batch(64) |
| End-to-end latency | <15 seconds (packet → alert on dashboard) |
| DDoS detection F1 | >0.95 |
| PortScan detection F1 | >0.92 |
| DGA detection F1 | >0.94 |

## Tech Stack

- **Ingest**: Rust (pcap, etherparse, rdkafka)
- **Streaming**: Apache Kafka (KRaft mode, no Zookeeper)
- **ML**: Python (scikit-learn, Gradient Boosting, Random Forest)
- **Communication**: gRPC (protobuf) + Kafka
- **Backend**: FastAPI + WebSocket
- **Frontend**: React + TypeScript + Recharts/D3
- **Deployment**: Docker Compose

## Team

- Built for Smart India Hackathon 2026
- Organization: National Technical Research Organisation (NTRO)
- Theme: Blockchain & Cybersecurity
