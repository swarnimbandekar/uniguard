#!/usr/bin/env python3
"""
Live PortScan Detection via Zeek → Model → Kafka → Dashboard

This script captures traffic in rolling chunks, runs Zeek (via Docker) to get
proper conn.log with conn_state fields, then feeds it through the calibrated
port scan model and pushes alerts to Kafka.

Flow:
  Network Interface (tshark capture, rolling 12s chunks)
       │
       ▼
  Zeek (Docker) — produces conn.log with proper conn_state (S0, REJ, SF...)
       │
       ▼
  PortScan Model (18 features, calibrated logistic regression)
       │
       ▼
  Adapter (transform to our alert schema)
       │
       ▼
  Kafka: threat-alerts → Dashboard (http://localhost:3000)

Usage (Run as Administrator):
  python scripts/live_portscan.py --iface "Wi-Fi"
  python scripts/live_portscan.py --iface "Wi-Fi" --chunk 15

Then in another terminal, run a scan:
  nmap -sS -T4 -p 1-1000 172.20.32.10
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml-service"))

from portscan.model import PortScanDetector
from portscan.sources import SourceStats, zeek_conn_log
from portscan.streaming import StreamingWindower

try:
    from confluent_kafka import Producer
except ImportError:
    print("ERROR: pip install confluent-kafka")
    sys.exit(1)


DEFAULT_MODEL = ROOT / "ml-service" / "models" / "portscan-10s2s.joblib"
KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "threat-alerts"


def adapt_alert(raw_alert) -> dict:
    """Transform model alert → our pipeline alert schema."""
    raw = raw_alert.as_dict() if hasattr(raw_alert, "as_dict") else raw_alert
    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": raw["window"]["start_ts"],
        "threat_class": "PortScan",
        "confidence": raw["confidence"],
        "severity": raw["severity"],
        "src_ip": raw["source_ip"],
        "dst_ip": "multiple",
        "src_port": 0,
        "dst_port": 0,
        "flow_id": f"{raw['source_ip']}:scan-multiple:0",
        "evidence": raw["evidence"],
        "model_version": "portscan-10s2s",
    }


def capture_chunk(iface: str, duration: int, output_pcap: Path) -> int:
    """Capture `duration` seconds of traffic with tshark. Returns packet count."""
    cmd = [
        "tshark", "-i", iface,
        "-a", f"duration:{duration}",
        "-w", str(output_pcap),
        "-q",  # quiet
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
    # Parse packet count from tshark stderr
    for line in result.stderr.splitlines():
        if "packets captured" in line.lower() or "packets" in line.lower():
            parts = line.strip().split()
            for p in parts:
                if p.isdigit():
                    return int(p)
    # Fallback: check file exists and has size
    if output_pcap.exists() and output_pcap.stat().st_size > 100:
        return -1  # unknown count but file exists
    return 0


def zeek_process(pcap_path: Path, work_dir: Path) -> Path | None:
    """Run Zeek on a PCAP via Docker, return path to conn.log."""
    # Wait for tshark to release the file
    time.sleep(1)

    # Mount the directory containing the pcap directly
    mount_dir = str(pcap_path.parent).replace("\\", "/")
    pcap_name = pcap_path.name

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{mount_dir}:/data",
        "-w", "/data",
        "zeek/zeek:latest",
        "zeek", "-r", f"/data/{pcap_name}", "LogAscii::use_json=T",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    conn_log = pcap_path.parent / "conn.log"
    if conn_log.exists() and conn_log.stat().st_size > 0:
        return conn_log
    return None


def run_model(detector: PortScanDetector, conn_log: Path, windower: StreamingWindower) -> list:
    """Run the model on a conn.log, return list of alerts."""
    alerts = []
    source_stats = SourceStats()

    try:
        for flow in zeek_conn_log(str(conn_log), source_stats):
            for window in windower.push(flow):
                alert = detector.alert_for(window, require_calibrated=True)
                if alert:
                    alerts.append(alert)
    except Exception as e:
        print(f"    [!] Model error: {e}", file=sys.stderr)

    # Flush remaining
    for window in windower.flush():
        alert = detector.alert_for(window, require_calibrated=True)
        if alert:
            alerts.append(alert)

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Live PortScan detection: Capture → Zeek → Model → Kafka → Dashboard")
    parser.add_argument("--iface", "-i", required=True,
                        help="Network interface (e.g. 'Wi-Fi', 'Ethernet 2')")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL,
                        help="Model artifact path")
    parser.add_argument("--kafka-broker", default=KAFKA_BROKER,
                        help=f"Kafka broker (default: {KAFKA_BROKER})")
    parser.add_argument("--chunk", type=int, default=12,
                        help="Capture chunk duration in seconds (default: 12)")
    parser.add_argument("--lateness", type=float, default=2,
                        help="Streaming lateness (default: 2s)")
    args = parser.parse_args()

    print("=" * 60)
    print("  LIVE PORTSCAN DETECTOR")
    print("  Capture → Zeek (Docker) → Model → Kafka → Dashboard")
    print("=" * 60)
    print(f"  Interface:    {args.iface}")
    print(f"  Chunk size:   {args.chunk}s capture → Zeek → score")
    print(f"  Model:        {args.model.name}")
    print(f"  Kafka:        {args.kafka_broker} → {KAFKA_TOPIC}")
    print(f"  Dashboard:    http://localhost:3000")
    print("=" * 60)
    print()

    # Verify tshark
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, timeout=5)
    except FileNotFoundError:
        print("[!] tshark not found. Install Wireshark.")
        sys.exit(1)

    # Verify Docker + Zeek image
    try:
        r = subprocess.run(["docker", "image", "inspect", "zeek/zeek:latest"],
                           capture_output=True, timeout=10)
        if r.returncode != 0:
            print("[!] zeek/zeek:latest image not found. Pull it:")
            print("    docker pull zeek/zeek:latest")
            sys.exit(1)
    except FileNotFoundError:
        print("[!] Docker not found.")
        sys.exit(1)

    # Load model
    print("[+] Loading model...")
    detector = PortScanDetector.load(args.model)
    print(f"    {detector.model_name} | threshold {detector.threshold:.4f} | "
          f"calibration {detector.calibration_method}")
    print(f"    Window: {detector.window_spec.window_seconds}s / "
          f"stride {detector.window_spec.stride_seconds}s / "
          f"min {detector.window_spec.min_flows} flows")
    print()

    # Kafka
    print("[+] Connecting to Kafka...")
    producer = Producer({"bootstrap.servers": args.kafka_broker, "linger.ms": "50"})
    print(f"    → {args.kafka_broker}")
    print()

    # Create working directory
    work_base = ROOT / "tmp_live"
    work_base.mkdir(exist_ok=True)

    total_alerts = 0
    total_chunks = 0
    total_flows = 0

    print(f"[+] Starting live capture loop on '{args.iface}'")
    print(f"    Each cycle: {args.chunk}s capture → Zeek → model → Kafka")
    print(f"    Press Ctrl+C to stop")
    print()
    print("-" * 60)

    try:
        while True:
            total_chunks += 1
            cycle_start = time.time()

            # Clean work dir
            work_dir = work_base / f"chunk_{total_chunks}"
            work_dir.mkdir(exist_ok=True)
            pcap_path = work_dir / "capture.pcap"

            # Step 1: Capture
            print(f"\n[Cycle {total_chunks}] Capturing {args.chunk}s on {args.iface}...", end="", flush=True)
            pkt_count = capture_chunk(args.iface, args.chunk, pcap_path)

            if pkt_count == 0 or not pcap_path.exists():
                print(f" no packets. Retrying...")
                shutil.rmtree(work_dir, ignore_errors=True)
                continue

            print(f" {pkt_count if pkt_count > 0 else '?'} packets")

            # Step 2: Zeek
            print(f"           Running Zeek...", end="", flush=True)
            conn_log = zeek_process(pcap_path, work_dir)

            if not conn_log:
                print(" no conn.log produced (no TCP/UDP flows?)")
                shutil.rmtree(work_dir, ignore_errors=True)
                continue

            log_size = conn_log.stat().st_size
            print(f" conn.log ({log_size} bytes)")

            # Step 3: Model
            print(f"           Scoring...", end="", flush=True)
            windower = StreamingWindower(
                spec=detector.window_spec,
                lateness_seconds=args.lateness,
            )
            alerts = run_model(detector, conn_log, windower)

            if not alerts:
                print(f" 0 alerts (traffic looks benign)")
            else:
                print(f" {len(alerts)} alert(s) detected!")

                # Step 4: Push to Kafka
                for alert in alerts:
                    adapted = adapt_alert(alert)
                    producer.produce(
                        topic=KAFKA_TOPIC,
                        key=adapted["src_ip"].encode("utf-8"),
                        value=json.dumps(adapted).encode("utf-8"),
                    )
                    total_alerts += 1

                    # Print details
                    raw = alert.as_dict()
                    print(f"\n    ┌─ ALERT ─────────────────────────────────")
                    print(f"    │ Threat:     PORT_SCAN")
                    print(f"    │ Severity:   {raw['severity']}")
                    print(f"    │ Confidence: {raw['confidence']*100:.1f}%")
                    print(f"    │ Source:     {raw['source_ip']}")
                    print(f"    │ Evidence:")
                    print(f"    │   Unique ports:   {raw['evidence']['unique_dst_ports']}")
                    print(f"    │   Connections:    {raw['evidence']['connection_attempts']}")
                    print(f"    │   Failed:         {raw['evidence']['failed_connections']}")
                    print(f"    │   Scan rate:      {raw['evidence']['scan_rate']:.1f}/s")
                    print(f"    │ Window:     {raw['window']['start']} → {raw['window']['end']}")
                    print(f"    └─ → Pushed to Kafka → Dashboard")

                producer.flush(3)

            # Cleanup
            shutil.rmtree(work_dir, ignore_errors=True)

            cycle_time = time.time() - cycle_start
            print(f"           Cycle time: {cycle_time:.1f}s | "
                  f"Total alerts: {total_alerts}")

    except KeyboardInterrupt:
        print(f"\n\n{'=' * 60}")
        print(f"  STOPPED")
        print(f"  Chunks processed: {total_chunks}")
        print(f"  Total alerts:     {total_alerts}")
        print(f"  Kafka topic:      {KAFKA_TOPIC}")
        print(f"  Dashboard:        http://localhost:3000")
        print(f"{'=' * 60}")
    finally:
        producer.flush(5)
        shutil.rmtree(work_base, ignore_errors=True)


if __name__ == "__main__":
    main()
