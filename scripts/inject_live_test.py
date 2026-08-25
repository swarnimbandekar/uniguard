"""
Inject test traffic directly to Kafka to simulate live capture.
Tests all 3 detection models: PortScan, DDoS, DGA.
"""

import json
import time
import random
from datetime import datetime
from confluent_kafka import Producer

producer = Producer({"bootstrap.servers": "localhost:9092", "linger.ms": "5"})
topic = "flow-records"

print("=" * 60)
print("  LIVE TEST - Injecting attack traffic into pipeline")
print("=" * 60)

# --- Phase 1: Port Scan (nmap-like) ---
print("\n[1/3] Simulating nmap port scan: 10.0.0.99 -> 192.168.56.1")
scanner_ip = "10.0.0.99"
target_ip = "192.168.56.1"
for port in range(1, 201):
    record = {
        "src_ip": scanner_ip,
        "dst_ip": target_ip,
        "src_port": random.randint(40000, 60000),
        "dst_port": port,
        "protocol": 6,
        "timestamp_us": int(time.time() * 1_000_000),
        "packet_len": 60,
        "payload_len": 0,
        "tcp_flags": {
            "syn": True, "ack": False, "rst": False,
            "fin": False, "psh": False, "urg": False,
        },
        "dns_query": None,
        "ingest_time": datetime.utcnow().isoformat(),
    }
    key = f"{scanner_ip}:{record['src_port']}-{target_ip}:{port}"
    producer.produce(topic, key=key.encode(), value=json.dumps(record).encode())
    producer.poll(0)
print("  -> Sent 200 SYN probes to ports 1-200")
print("  -> Expected: PortScan detection (high unique_dst_ports)")

# --- Phase 2: DDoS SYN flood ---
print("\n[2/3] Simulating DDoS SYN flood -> 192.168.56.1:80")
for i in range(500):
    src = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    record = {
        "src_ip": src,
        "dst_ip": "192.168.56.1",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "protocol": 6,
        "timestamp_us": int(time.time() * 1_000_000) + i * 100,
        "packet_len": 60,
        "payload_len": 0,
        "tcp_flags": {
            "syn": True, "ack": False, "rst": False,
            "fin": False, "psh": False, "urg": False,
        },
        "dns_query": None,
        "ingest_time": datetime.utcnow().isoformat(),
    }
    producer.produce(topic, value=json.dumps(record).encode())
    producer.poll(0)
print("  -> Sent 500 SYN floods from random spoofed IPs")
print("  -> Expected: DDoS detection (high packet rate, all SYN, no ACK)")

# --- Phase 3: DGA DNS queries ---
print("\n[3/3] Simulating DGA DNS tunneling from 192.168.1.50")
chars = "abcdefghijklmnopqrstuvwxyz0123456789"
tlds = [".com", ".net", ".org", ".xyz", ".top"]
generated_domains = []
for i in range(50):
    domain = "".join(random.choices(list(chars), k=random.randint(12, 22))) + random.choice(tlds)
    generated_domains.append(domain)
    record = {
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8",
        "src_port": random.randint(1024, 65535),
        "dst_port": 53,
        "protocol": 17,
        "timestamp_us": int(time.time() * 1_000_000) + i * 10000,
        "packet_len": 80,
        "payload_len": 40,
        "tcp_flags": None,
        "dns_query": domain,
        "ingest_time": datetime.utcnow().isoformat(),
    }
    producer.produce(topic, value=json.dumps(record).encode())
    producer.poll(0)
print(f"  -> Sent 50 DGA-like DNS queries")
print(f"  -> Sample domains: {generated_domains[:3]}")
print(f"  -> Expected: DGA detection (high entropy, random chars)")

producer.flush(5)

print("\n" + "=" * 60)
print("  Traffic injected. Waiting for detection (10s window)...")
print("=" * 60)

# Wait for feature extraction window
time.sleep(12)

# Check results
import requests
try:
    resp = requests.get("http://localhost:8001/api/stats", timeout=5)
    if resp.status_code == 200:
        stats = resp.json()
        print("\n  RESULTS:")
        print(f"  Total alerts: {stats['total_alerts']}")
        print(f"  By threat class: {stats['by_threat_class']}")
        print(f"  By severity: {stats['by_severity']}")
        print(f"  Top sources: {stats['top_sources']}")

        # Get recent alerts
        resp2 = requests.get("http://localhost:8001/api/alerts/recent?limit=5", timeout=5)
        if resp2.status_code == 200:
            alerts = resp2.json()["alerts"]
            print(f"\n  Latest alerts:")
            for a in alerts:
                print(f"    [{a['severity']}] {a['threat_class']} | {a['src_ip']} -> {a['dst_ip']} | confidence: {a['confidence']:.4f}")
    print("\n  Dashboard: http://localhost:3000")
except Exception as e:
    print(f"\n  Could not fetch results: {e}")
    print("  Check dashboard manually: http://localhost:3000")
