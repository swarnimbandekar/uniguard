# AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

> Smart India Hackathon 2026 | NTRO Problem Statement
> Real-time threat detection pipeline for read-only, unidirectional traffic monitoring

## Overview

A streaming network-detection pipeline that identifies **six classes of cyber threats**
from passively captured, read-only traffic — analyzing only flow metadata, never
decrypting payloads. Alerts surface on a live SOC dashboard within one detection window.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        UNIDIRECTIONAL TRAFFIC FLOW                         │
│                         (Read-Only, No Return Path)                        │
└────────────────────────────────────┬───────────────────────────────────────┘
                                      │ Live Capture / PCAP / Mirrored Traffic
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│  INGEST LAYER                                                            │
│  Option A: Rust PCAP Ingest — zero-copy parsing at 10,000+ pkt/s        │
│  Option B: Python Live Capture — scapy on Wi-Fi/Ethernet (Windows)      │
│  • Parses: 5-tuple, TCP flags, DNS queries, packet sizes                │
│  • Filters: multicast, broadcast, mDNS, SSDP                            │
│  • Produces JSON records to Kafka                                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                     │ Kafka: flow-records
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  FEATURE EXTRACTION + DETECTION SERVICE                                  │
│  • Aggregates packets into flows (10s tumbling windows)                  │
│  • Runs 5 detectors LOCALLY (no gRPC) at window boundaries:              │
│      PortScan · DDoS · Encrypted Malware · Data Exfiltration · C2 Beacon │
│  • DGA runs via gRPC call to the inference server                        │
└───────────────┬───────────────────────────────────┬────────────────────┘
                │ gRPC (DGA Inference)               │ Kafka: threat-alerts
                ▼                                     ▼
┌──────────────────────────────────┐  ┌─────────────────────────────────┐
│  ML INFERENCE SERVER (gRPC)      │  │  FASTAPI BACKEND                 │
│  • DGA: GradientBoosting +       │  │  • Consumes alerts from Kafka    │
│         char n-grams             │  │  • WebSocket real-time push      │
│  • Batch inference: <50ms        │  │  • REST API for history/stats    │
└──────────────────────────────────┘  └───────────────┬─────────────────┘
                                                       │ WebSocket
                                                       ▼
                                       ┌─────────────────────────────────┐
                                       │  REACT SOC DASHBOARD             │
                                       │  • Real-time alert feed          │
                                       │  • Threat timeline (stacked)     │
                                       │  • Severity distribution         │
                                       │  • Top attacker IPs              │
                                       │  • Detection-engine status panel │
                                       │  • Alert detail drill-down       │
                                       └─────────────────────────────────┘
```

## Detection Modules

All six threat classes are **ACTIVE** and verified live against Metasploitable 2.

| # | Module | Threat Class | Model / Method | Features | Throughput |
|---|--------|-------------|----------------|----------|------------|
| 1 | **Recon / Port Scan** | `PortScan` | Calibrated Logistic Regression + streaming windower | 18 | streaming |
| 2 | **Volumetric DDoS** | `DDoS` | HistGradientBoosting + per-destination aggregation | 31 | 95K flows/s |
| 3 | **DGA & DNS Tunnel** | `DGA` | Gradient Boosting + char n-grams (2,3) | 19 + 200 n-grams | gRPC |
| 4 | **C2 Beaconing** | `C2_BEACONING` | Inter-arrival periodicity analysis (jitter CV) | temporal | streaming |
| 5 | **Encrypted Malware** | `EncryptedMalware` | HistGradientBoosting on flow metadata (non-std ports) | 31 | 42K flows/s |
| 6 | **Data Exfiltration** | `DataExfiltration` | HistGradientBoosting + asymmetric-upload rule | 29 | 77K flows/s |

**Design note:** Detectors 2, 5, 6 are ML models trained on synthetic behavioral data
augmented with deterministic rule overrides for unambiguous signatures. Detector 4
(C2 Beaconing) is a purpose-built periodicity analyzer — it flags a host that repeatedly
contacts the same destination at near-constant intervals (low inter-arrival jitter), the
classic "phone-home" fingerprint. All detectors operate on metadata only.

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.11+ (for live capture and testing)
- Npcap (Windows, for live network capture)
- Nmap (for port-scan / attack demos)

### 1. Start the Pipeline

```bash
docker compose up --build -d
```

Starts: Kafka, ML Inference Server, Feature Extractor, Backend, Dashboard.

### 2. Access the Dashboard

Open http://localhost:3000

### 3. Run a Detection Demo

**Option A — Inject synthetic traffic (no capture, no VM needed):**
```powershell
python scripts/inject_all_threats.py
```

**Option B — Live capture + real attacks against a target VM:**

Terminal 1 (as Administrator) — start the sniffer:
```powershell
python scripts/live_capture.py --interface "Ethernet 2" --target 192.168.56.101
```

Terminal 2 — clear the board, then attack:
```powershell
# Clear existing alerts
Invoke-RestMethod -Method POST -Uri "http://localhost:8001/api/alerts/clear"

# Run all six attacks in sequence
python scripts/attack_metasploitable.py

# Or run one at a time
python scripts/attack_metasploitable.py --only portscan
python scripts/attack_metasploitable.py --only ddos
python scripts/attack_metasploitable.py --only exfil
python scripts/attack_metasploitable.py --only c2
python scripts/attack_metasploitable.py --only dga
```

Alerts appear on the dashboard within ~10–15 seconds (one detection window).

> **Interface name:** run `python scripts/list_interfaces.py` to find the exact name
> scapy expects for your capture adapter.

## Lab Setup (Live Attack Demo)

```
Windows Host (sniffer + Docker pipeline + dashboard)
   │  Host-Only network 192.168.56.0/24  (adapter "Ethernet 2", 192.168.56.1)
   ▼
Metasploitable 2 VM (victim)  192.168.56.101
```

- VirtualBox: create a **Host-Only** network, attach Metasploitable's adapter to it.
- Attack from the Windows host directly to `192.168.56.101` so the host sniffs all traffic.
- DNS-based DGA queries are directed at the target's own resolver (`:53`) so they cross
  the monitored interface.

## Project Structure

```
sih/
├── docker-compose.yml              # Full pipeline orchestration
├── ingest/                         # Rust PCAP ingest service
│   ├── Cargo.toml · Dockerfile · src/main.rs
├── ml-service/                     # Python ML pipeline
│   ├── feature_extractor.py        # Kafka consumer + all local detectors + DGA gRPC
│   ├── inference_server.py         # gRPC inference server (DGA)
│   ├── models/                     # Trained model artifacts (6 detectors)
│   │   ├── portscan-10s2s.joblib
│   │   ├── ddos_flow.joblib (+ .metadata.json)
│   │   ├── encrypted_malware_flow.joblib (+ .metadata.json)
│   │   ├── exfiltration_flow.joblib (+ .metadata.json)
│   │   ├── dga_gb.pkl · dga_vectorizer.pkl · dga_features.pkl · dga_metadata.json
│   ├── portscan/                   # Port scan module (features, streaming, model, alert)
│   ├── ddos/                       # DDoS detector module
│   ├── encrypted_malware/          # Encrypted malware flow detector module
│   ├── exfiltration/               # Data exfiltration detector module
│   ├── c2beacon/                   # C2 beaconing periodicity detector module
│   ├── train_all_models.py         # Trains DDoS + Exfiltration models
│   ├── train_encrypted_malware.py  # Trains the encrypted-malware flow model
│   ├── retrain_dga.py              # DGA model retraining
│   ├── train.py                    # Legacy training reference
│   ├── predict_portscan.py         # Standalone portscan CLI
│   ├── proto/                      # gRPC protobuf definitions
│   ├── Dockerfile.extractor · Dockerfile.inference · requirements.txt
├── backend/                        # FastAPI WebSocket backend
│   ├── main.py · Dockerfile
├── dashboard/                      # React + TypeScript SOC dashboard
│   ├── src/App.tsx · Dockerfile · nginx.conf
├── proto/                          # Shared protobuf definitions
│   └── inference.proto
├── scripts/                        # Testing and attack utilities
│   ├── live_capture.py             # Live network capture → Kafka
│   ├── attack_metasploitable.py    # Live attacks for all 6 threats
│   ├── inject_all_threats.py       # Inject synthetic traffic for all threats
│   ├── list_interfaces.py          # List capture interfaces (scapy names)
│   ├── live_portscan.py            # Standalone portscan (Zeek-based)
│   ├── test_dga.py                 # DGA model evaluation
│   ├── generate_traffic.py         # Generate test PCAPs
│   └── integration_test.py         # Full pipeline integration test
├── data/pcaps/ · data/examples/    # Test PCAPs and sample logs
├── c2_beaconing_detector/          # Reference C2 detector docs + schema (superseded by ml-service/c2beacon/)
├── ARCHITECTURE.md · Makefile · README.md
```

## Architectural Constraints

| Constraint | Implementation |
|---|---|
| **Read-only ingest** | Passive capture only; no write-back to the network |
| **No payload decryption** | All analysis on metadata: IP headers, TCP flags, DNS queries, timing |
| **Streaming, not batch** | 10-second tumbling windows, bounded end-to-end latency (<15s) |
| **Throughput target** | 10,000+ pkt/s (Rust ingest); models score 42K–95K flows/s |
| **Standardized alerts** | JSON schema: timestamp, flow_id, threat_class, confidence, severity, evidence |
| **Bounded memory** | Streaming windower + per-endpoint trackers with stale eviction |

## Alert Schema

```json
{
  "alert_id": "uuid-v4",
  "timestamp": 1724625000.123,
  "threat_class": "C2_BEACONING",
  "confidence": 0.978,
  "severity": "CRITICAL",
  "src_ip": "192.168.56.1",
  "dst_ip": "192.168.56.101",
  "src_port": 0,
  "dst_port": 1524,
  "flow_id": "192.168.56.1:0-192.168.56.101:1524",
  "evidence": {
    "beacon_count": 20,
    "mean_interval_sec": 1.55,
    "jitter_cv": 0.012,
    "interval_std_sec": 0.02,
    "total_bytes": 12400
  },
  "model_version": "1.0.0"
}
```

## Model Performance (validation)

| Model | ROC-AUC | F1 | FPR | Threshold | Throughput |
|---|---|---|---|---|---|
| DDoS | 1.000 | 1.000 | 0.000 | 0.92 | 95,504 flows/s |
| Encrypted Malware | 1.000 | 0.9999 | 0.000 | 0.28 | 42,045 flows/s |
| Data Exfiltration | 1.000 | 0.9999 | 5e-5 | 0.99 | 76,863 flows/s |
| DGA | — | >0.98 | — | — | gRPC batch |
| Port Scan | — | calibrated | — | 0.60 | streaming |

> Flow-model metrics are on held-out synthetic validation data; production behavior is
> further constrained by rule overrides and minimum-volume guards to suppress false
> positives on real traffic.

## Latency Budget

| Stage | Value |
|---|---|
| Ingest throughput | 10,000+ pkt/s (Rust) / 3,000+ pkt/s (Python live) |
| Detection window | 10 seconds (tumbling) |
| ML inference | <10ms single, <50ms batch |
| End-to-end (packet → dashboard) | <15 seconds |

## Tech Stack

- **Ingest**: Rust (pcap, etherparse, rdkafka) / Python (scapy)
- **Streaming**: Apache Kafka (KRaft mode, no Zookeeper)
- **ML**: scikit-learn (HistGradientBoosting, GradientBoosting, Logistic Regression)
- **Communication**: gRPC (protobuf) + Kafka
- **Backend**: FastAPI + WebSocket
- **Frontend**: React 18 + TypeScript + Recharts
- **Deployment**: Docker Compose

## Team

Smart India Hackathon 2026
Organization: National Technical Research Organisation (NTRO)
Theme: Blockchain & Cybersecurity
