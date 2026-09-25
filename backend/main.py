"""
FastAPI Backend for Threat Detection Dashboard.
Consumes alerts from Kafka and streams them to the dashboard via WebSocket.
Provides REST endpoints for historical alerts and statistics.
"""

import asyncio
import json
import logging
import os
import random
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from threading import Thread
from typing import List, Optional

from confluent_kafka import Consumer, KafkaError, Producer
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Configuration
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "threat-alerts")

# In-memory storage
MAX_ALERTS = 10000
alerts_store: deque = deque(maxlen=MAX_ALERTS)
stats = {
    "total_alerts": 0,
    "by_threat_class": defaultdict(int),
    "by_severity": defaultdict(int),
    "alerts_per_minute": 0,
    "top_sources": defaultdict(int),
    "start_time": time.time(),
}

# WebSocket connections
ws_connections: List[WebSocket] = []


# --- Pydantic Models ---

class Alert(BaseModel):
    alert_id: str
    timestamp: float
    threat_class: str
    confidence: float
    severity: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    flow_id: str
    evidence: dict
    model_version: str


class StatsResponse(BaseModel):
    total_alerts: int
    by_threat_class: dict
    by_severity: dict
    alerts_per_minute: float
    top_sources: dict
    uptime_seconds: float


class AlertsResponse(BaseModel):
    alerts: List[dict]
    total: int
    page: int
    page_size: int


# --- Kafka Consumer Thread ---

def kafka_consumer_loop():
    """Background thread that consumes alerts from Kafka."""
    logger.info(f"Starting Kafka consumer for topic: {KAFKA_TOPIC}")

    consumer = Consumer({
        "bootstrap.servers": KAFKA_BROKER,
        "group.id": "dashboard-backend-group",
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,
        "session.timeout.ms": 30000,
    })
    consumer.subscribe([KAFKA_TOPIC])

    try:
        while True:
            msg = consumer.poll(timeout=0.5)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error(f"Kafka error: {msg.error()}")
                continue

            try:
                alert_data = json.loads(msg.value().decode("utf-8"))
                _process_alert(alert_data)
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Invalid alert message: {e}")

    except Exception as e:
        logger.error(f"Kafka consumer error: {e}")
    finally:
        consumer.close()


def _process_alert(alert_data: dict):
    """Process incoming alert: store and broadcast to WebSocket clients."""
    alerts_store.append(alert_data)

    # Update stats
    stats["total_alerts"] += 1
    stats["by_threat_class"][alert_data.get("threat_class", "UNKNOWN")] += 1
    stats["by_severity"][alert_data.get("severity", "UNKNOWN")] += 1
    stats["top_sources"][alert_data.get("src_ip", "unknown")] += 1

    # Calculate alerts per minute
    elapsed = time.time() - stats["start_time"]
    if elapsed > 0:
        stats["alerts_per_minute"] = stats["total_alerts"] / (elapsed / 60.0)

    # Broadcast to WebSocket clients
    asyncio.run(_broadcast_alert(alert_data))


async def _broadcast_alert(alert_data: dict):
    """Send alert to all connected WebSocket clients."""
    if not ws_connections:
        return

    message = json.dumps(alert_data)
    disconnected = []

    for ws in ws_connections:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)

    for ws in disconnected:
        ws_connections.remove(ws)


# --- FastAPI App ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start Kafka consumer on app startup."""
    consumer_thread = Thread(target=kafka_consumer_loop, daemon=True)
    consumer_thread.start()
    logger.info("Backend started. Kafka consumer running.")
    yield
    logger.info("Backend shutting down.")


app = FastAPI(
    title="Threat Detection Dashboard API",
    description="Real-time cyber threat detection alerts and statistics",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- REST Endpoints ---

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "uptime_seconds": time.time() - stats["start_time"],
        "total_alerts": stats["total_alerts"],
        "ws_connections": len(ws_connections),
    }


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get aggregate statistics."""
    return StatsResponse(
        total_alerts=stats["total_alerts"],
        by_threat_class=dict(stats["by_threat_class"]),
        by_severity=dict(stats["by_severity"]),
        alerts_per_minute=round(stats["alerts_per_minute"], 2),
        top_sources=dict(
            sorted(stats["top_sources"].items(), key=lambda x: x[1], reverse=True)[:20]
        ),
        uptime_seconds=round(time.time() - stats["start_time"], 1),
    )


@app.get("/api/alerts", response_model=AlertsResponse)
async def get_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    threat_class: Optional[str] = None,
    severity: Optional[str] = None,
):
    """Get paginated alerts with optional filtering."""
    filtered = list(alerts_store)

    if threat_class:
        filtered = [a for a in filtered if a.get("threat_class") == threat_class]
    if severity:
        filtered = [a for a in filtered if a.get("severity") == severity]

    # Sort by timestamp descending (most recent first)
    filtered.sort(key=lambda x: x.get("timestamp", 0), reverse=True)

    # Paginate
    start = (page - 1) * page_size
    end = start + page_size
    page_data = filtered[start:end]

    return AlertsResponse(
        alerts=page_data,
        total=len(filtered),
        page=page,
        page_size=page_size,
    )


@app.get("/api/alerts/recent")
async def get_recent_alerts(limit: int = Query(20, ge=1, le=100)):
    """Get most recent alerts."""
    recent = list(alerts_store)[-limit:]
    recent.reverse()
    return {"alerts": recent, "count": len(recent)}


@app.post("/api/alerts/clear")
async def clear_alerts():
    """Clear all alerts and reset statistics."""
    alerts_store.clear()
    stats["total_alerts"] = 0
    stats["by_threat_class"] = defaultdict(int)
    stats["by_severity"] = defaultdict(int)
    stats["top_sources"] = defaultdict(int)
    stats["start_time"] = time.time()
    logger.info("All alerts cleared and stats reset")
    return {"status": "cleared", "message": "All alerts and stats have been reset"}


@app.get("/api/alerts/timeline")
async def get_timeline(window_minutes: int = Query(5, ge=1, le=60)):
    """Get alert counts over time for timeline chart."""
    now = time.time()
    window_start = now - (window_minutes * 60)
    bucket_size = 10  # 10-second buckets

    buckets = defaultdict(lambda: defaultdict(int))

    for alert in alerts_store:
        ts = alert.get("timestamp", 0)
        if ts >= window_start:
            bucket_key = int(ts // bucket_size) * bucket_size
            threat_class = alert.get("threat_class", "UNKNOWN")
            buckets[bucket_key][threat_class] += 1

    timeline = []
    for bucket_ts in sorted(buckets.keys()):
        entry = {"timestamp": bucket_ts, "counts": dict(buckets[bucket_ts])}
        entry["total"] = sum(buckets[bucket_ts].values())
        timeline.append(entry)

    return {"timeline": timeline, "window_minutes": window_minutes}


# --- WebSocket Endpoint ---

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert streaming."""
    await websocket.accept()
    ws_connections.append(websocket)
    logger.info(f"WebSocket client connected. Total: {len(ws_connections)}")

    try:
        # Send last 10 alerts immediately on connect
        recent = list(alerts_store)[-10:]
        for alert in recent:
            await websocket.send_text(json.dumps(alert))

        # Keep connection alive
        while True:
            # Wait for client messages (ping/pong or disconnect)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                # Send keepalive
                await websocket.send_text(json.dumps({"type": "heartbeat", "timestamp": time.time()}))

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        if websocket in ws_connections:
            ws_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(ws_connections)}")


# --- Demo / Attack Simulation ---

demo_state = {
    "running": False,
    "phase": "",
    "progress": 0,   # 0-100
    "started_at": None,
}


def _demo_producer() -> Producer:
    return Producer({
        "bootstrap.servers": KAFKA_BROKER,
        "acks": "1",
        "queue.buffering.max.messages": "100000",
    })


def _make_pkt(src_ip, dst_ip, src_port, dst_port, protocol=6,
              pkt_len=200, payload_len=100,
              tcp_flags=None, dns_query=None) -> dict:
    if tcp_flags is None:
        tcp_flags = {"syn": False, "ack": True, "rst": False,
                     "fin": False, "psh": True, "urg": False}
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": protocol,
        "timestamp_us": int(time.time() * 1_000_000),
        "packet_len": pkt_len, "payload_len": payload_len,
        "tcp_flags": tcp_flags, "dns_query": dns_query,
        "ingest_time": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _send(producer: Producer, pkt: dict):
    topic = os.environ.get("KAFKA_FLOW_TOPIC", "flow-records")
    key = f"{pkt['src_ip']}:{pkt['src_port']}-{pkt['dst_ip']}:{pkt['dst_port']}"
    producer.produce(topic, key=key.encode(), value=json.dumps(pkt).encode())
    producer.poll(0)


def _run_demo():
    """Runs the full attack simulation in a background thread."""
    global demo_state
    demo_state.update({"running": True, "phase": "Starting…", "progress": 0,
                       "started_at": time.time()})
    try:
        p = _demo_producer()
        syn = {"syn": True,  "ack": False, "rst": False, "fin": False, "psh": False, "urg": False}
        ack = {"syn": False, "ack": True,  "rst": False, "fin": False, "psh": False, "urg": False}
        psh = {"syn": False, "ack": True,  "rst": False, "fin": False, "psh": True,  "urg": False}
        rst = {"syn": False, "ack": False, "rst": True,  "fin": False, "psh": False, "urg": False}

        # ── Benign background helper ───────────────────────────────────
        def send_benign(n: int = 80):
            """Interleave realistic benign traffic to raise model uncertainty."""
            legit = ["172.217.16.46", "151.101.1.140", "13.227.220.1",
                     "8.8.4.4", "93.184.216.34"]
            internal = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
            for _ in range(n):
                src = random.choice(internal)
                dst = random.choice(legit)
                proto = random.choice(["https", "dns", "http"])
                if proto == "dns":
                    words = ["google", "github", "amazon", "microsoft", "apple"]
                    domain = random.choice(words) + ".com"
                    _send(p, _make_pkt(src, "8.8.8.8",
                                       random.randint(1024, 65535), 53,
                                       protocol=17, pkt_len=random.randint(68, 82),
                                       payload_len=random.randint(40, 55),
                                       tcp_flags=None, dns_query=domain))
                else:
                    port = 443 if proto == "https" else 80
                    flag = random.choice([psh, ack])
                    _send(p, _make_pkt(src, dst,
                                       random.randint(1024, 65535), port,
                                       pkt_len=random.randint(200, 900),
                                       payload_len=random.randint(150, 850),
                                       tcp_flags=flag))

        # ── Phase 1: DDoS — three tiers, DIFFERENT destination IPs ──────
        # Each dst is scored independently by the feature extractor
        # Tier A: dst=192.168.1.100, 2500 pkts at max rate → score 0.99 → CRITICAL
        # Tier B: dst=192.168.1.101, 400 pkts, pkt_rate ~40/s → score ~0.91 → HIGH
        # Tier C: dst=10.0.0.5,       150 pkts, pkt_rate ~15/s → score ~0.90 → MEDIUM
        demo_state["phase"] = "DDoS SYN flood"
        logger.info("[DEMO] Phase 1 – DDoS SYN flood (intensity tiers)")

        # Tier A — CRITICAL
        for i in range(2500):
            src = f"{random.randint(1,223)}.{random.randint(0,255)}." \
                  f"{random.randint(0,255)}.{random.randint(1,254)}"
            _send(p, _make_pkt(src, "192.168.1.100",
                               random.randint(1024, 65535), 80,
                               pkt_len=60, payload_len=0, tcp_flags=syn))
            if i % 500 == 499: p.flush()
        p.flush()

        # Tier B — HIGH: fewer packets, mixed flags, different dst
        send_benign(30)
        for i in range(400):
            src = f"{random.randint(1,223)}.{random.randint(0,255)}." \
                  f"{random.randint(0,255)}.{random.randint(1,254)}"
            flag = syn if random.random() < 0.70 else ack
            _send(p, _make_pkt(src, "192.168.1.101",
                               random.randint(1024, 65535), random.choice([80, 443]),
                               pkt_len=random.randint(54, 90), payload_len=0,
                               tcp_flags=flag))
            if i % 100 == 99: p.flush()
        p.flush()

        # Tier C — MEDIUM: low rate, noisy, different dst
        send_benign(50)
        for i in range(150):
            src = f"{random.randint(1,223)}.{random.randint(0,255)}." \
                  f"{random.randint(0,255)}.{random.randint(1,254)}"
            _send(p, _make_pkt(src, "10.0.0.5",
                               random.randint(1024, 65535), 8080,
                               pkt_len=random.randint(54, 120), payload_len=0,
                               tcp_flags=syn))
            if i % 50 == 49: p.flush()
        send_benign(30)
        p.flush()
        demo_state["progress"] = 20

        # ── Phase 2: Port scan — two scanners, varied port coverage ────
        # Scanner A: 500 ports → model score near 1.0 → CRITICAL
        # Scanner B: 25 ports  → lower score → MEDIUM/LOW
        demo_state["phase"] = "Port scan reconnaissance"
        logger.info("[DEMO] Phase 2 – Port scan (varied coverage)")

        ports_a = list(range(1, 501))
        random.shuffle(ports_a)
        for i, port in enumerate(ports_a):
            _send(p, _make_pkt("10.10.10.10", "192.168.1.200",
                               random.randint(40000, 60000), port,
                               pkt_len=random.randint(54, 66), payload_len=0,
                               tcp_flags=syn))
            if random.random() < 0.92:
                _send(p, _make_pkt("192.168.1.200", "10.10.10.10", port,
                                   random.randint(40000, 60000),
                                   pkt_len=54, payload_len=0, tcp_flags=rst))
            if i % 100 == 99: p.flush()
        p.flush()

        send_benign(30)
        # Scanner B: only 25 ports (still above the unique_ports >= 10 gate)
        ports_b = random.sample(range(1, 1024), 25)
        for i, port in enumerate(ports_b):
            _send(p, _make_pkt("172.16.0.99", "192.168.1.201",
                               random.randint(40000, 60000), port,
                               pkt_len=random.randint(54, 70), payload_len=0,
                               tcp_flags=syn))
            if random.random() < 0.70:
                _send(p, _make_pkt("192.168.1.201", "172.16.0.99", port,
                                   random.randint(40000, 60000),
                                   pkt_len=54, payload_len=0, tcp_flags=rst))
        p.flush()
        demo_state["progress"] = 37

        # ── Phase 3: DGA — three entropy tiers ─────────────────────────
        demo_state["phase"] = "DGA / DNS tunnelling"
        logger.info("[DEMO] Phase 3 – DGA (entropy tiers)")
        chars  = "abcdefghijklmnopqrstuvwxyz0123456789"
        vowels = "aeiou"
        cons   = "bcdfghjklmnpqrstvwxyz"
        tlds   = [".com", ".net", ".org", ".info", ".xyz", ".top"]

        # Tier A: 20–26 char random → very high entropy → CRITICAL
        for _ in range(50):
            domain = "".join(random.choices(chars, k=random.randint(20, 26))) \
                     + random.choice(tlds)
            _send(p, _make_pkt("192.168.1.50", "8.8.8.8",
                               random.randint(1024, 65535), 53,
                               protocol=17, pkt_len=random.randint(80, 96),
                               payload_len=random.randint(55, 72),
                               tcp_flags=None, dns_query=domain))

        # Tier B: 12–17 char mixed → medium entropy → HIGH
        for _ in range(30):
            domain = "".join(random.choices(chars, k=random.randint(12, 17))) \
                     + random.choice(tlds)
            _send(p, _make_pkt("192.168.1.51", "8.8.8.8",
                               random.randint(1024, 65535), 53,
                               protocol=17, pkt_len=random.randint(72, 85),
                               payload_len=random.randint(48, 60),
                               tcp_flags=None, dns_query=domain))

        # Tier C: 8–11 char, alternating consonant-vowel → resembles real words → MEDIUM/LOW
        for _ in range(20):
            pattern = ""
            for j in range(random.randint(8, 11)):
                pattern += random.choice(vowels if j % 2 else cons)
            domain = pattern + random.choice([".com", ".net"])
            _send(p, _make_pkt("192.168.1.51", "8.8.8.8",
                               random.randint(1024, 65535), 53,
                               protocol=17, pkt_len=random.randint(68, 78),
                               payload_len=random.randint(40, 52),
                               tcp_flags=None, dns_query=domain))

        send_benign(20)
        p.flush()
        demo_state["progress"] = 50

        # ── Phase 4: Encrypted malware — real-time spread ─────────────
        demo_state["phase"] = "Encrypted malware traffic"
        logger.info("[DEMO] Phase 4 – Encrypted malware")
        enc_pairs = [
            ("10.20.30.40", "91.230.14.11",   4444),
            ("10.20.30.41", "185.220.101.55",  7788),
            ("10.20.30.42", "94.102.49.190",   6667),
        ]
        for idx, (enc_src, enc_dst, enc_port) in enumerate(enc_pairs):
            sport = random.randint(40000, 58000)
            _send(p, _make_pkt(enc_src, enc_dst, sport, enc_port,
                               pkt_len=60, payload_len=0, tcp_flags=syn))
            p.flush()
            # Vary packet count per pair: 14, 10, 8 → different flow volumes
            pkt_counts = [14, 10, 8]
            n = pkt_counts[idx]
            for i in range(n):
                time.sleep(0.55)
                _send(p, _make_pkt(enc_src, enc_dst, sport, enc_port,
                                   pkt_len=random.randint(110, 160),
                                   payload_len=random.randint(80, 130),
                                   tcp_flags=psh))
                if i % 3 == 2:
                    _send(p, _make_pkt(enc_dst, enc_src, enc_port, sport,
                                       pkt_len=random.randint(220, 310),
                                       payload_len=random.randint(180, 270),
                                       tcp_flags=psh))
                p.flush()
            demo_state["progress"] = 50 + int((idx + 1) / len(enc_pairs) * 13)
        demo_state["progress"] = 63

        # ── Phase 5: C2 beaconing — two pairs, different jitter ────────
        # Pair A: tight 2s interval (cv≈0) → CRITICAL
        # Pair B: looser interval with jitter (cv≈0.25) → HIGH
        demo_state["phase"] = "C2 beaconing"
        logger.info("[DEMO] Phase 5 – C2 beaconing")
        c2_pairs = [
            ("10.30.40.50", "91.234.56.78",    9001, 2.0, 0.05),   # tight
            ("10.30.40.51", "45.142.212.100",   4443, 2.0, 0.40),  # jittery
        ]
        beacons_per_pair = 8
        base_ts_c2 = int(time.time() * 1_000_000)
        for beat in range(beacons_per_pair):
            for c2_src, c2_dst, c2_port, interval, jitter_cv in c2_pairs:
                actual_iv = interval * (1 + random.uniform(-jitter_cv, jitter_cv))
                offset_us = int(beat * interval * 1_000_000)
                sport = random.randint(49000, 55000)
                syn_pkt = _make_pkt(c2_src, c2_dst, sport, c2_port,
                                    pkt_len=60, payload_len=0, tcp_flags=syn)
                syn_pkt["timestamp_us"] = base_ts_c2 + offset_us
                _send(p, syn_pkt)
                data_pkt = _make_pkt(c2_src, c2_dst, sport, c2_port,
                                     pkt_len=random.randint(100, 145),
                                     payload_len=random.randint(65, 105),
                                     tcp_flags=psh)
                data_pkt["timestamp_us"] = base_ts_c2 + offset_us + 20_000
                _send(p, data_pkt)
                resp_pkt = _make_pkt(c2_dst, c2_src, c2_port, sport,
                                     pkt_len=random.randint(320, 460),
                                     payload_len=random.randint(280, 420),
                                     tcp_flags=psh)
                resp_pkt["timestamp_us"] = base_ts_c2 + offset_us + 50_000
                _send(p, resp_pkt)
            p.flush()
            if beat < beacons_per_pair - 1:
                time.sleep(2.0)
            demo_state["progress"] = 63 + int((beat + 1) / beacons_per_pair * 20)
        p.flush()
        demo_state["progress"] = 83

        # ── Phase 6: Exfiltration — two pairs, different upload ratio ──
        # Pair A: 350 pkts upload, 4 ACKs → score ≈ 1.0 (CRITICAL)
        # Pair B: 120 pkts upload, 20 ACKs → lower ratio → HIGH/MEDIUM
        demo_state["phase"] = "Data exfiltration"
        logger.info("[DEMO] Phase 6 – Data exfiltration (varied intensity)")
        exf_scenarios = [
            ("192.168.1.60", "185.100.200.50", 443,  350, 4),
            ("192.168.1.61", "104.21.90.77",   8443, 120, 20),
        ]
        for exf_src, exf_dst, exf_port, up_pkts, dn_pkts in exf_scenarios:
            sport = random.randint(50000, 53000)
            _send(p, _make_pkt(exf_src, exf_dst, sport, exf_port,
                               pkt_len=60, payload_len=0, tcp_flags=syn))
            for i in range(up_pkts):
                _send(p, _make_pkt(exf_src, exf_dst, sport, exf_port,
                                   pkt_len=random.randint(1200, 1460),
                                   payload_len=random.randint(1100, 1400),
                                   tcp_flags=psh))
                if i % 100 == 99: p.flush()
            for _ in range(dn_pkts):
                _send(p, _make_pkt(exf_dst, exf_src, exf_port, sport,
                                   pkt_len=random.randint(60, 200),
                                   payload_len=random.randint(20, 160),
                                   tcp_flags=ack))
            p.flush()
        demo_state["progress"] = 100

    except Exception as e:
        logger.error(f"[DEMO] Error during simulation: {e}")
    finally:
        demo_state.update({"running": False, "phase": "Complete", "progress": 100})
        logger.info("[DEMO] Simulation complete")


@app.post("/api/demo")
async def start_demo():
    """Trigger a full multi-threat attack simulation into the pipeline."""
    if demo_state["running"]:
        raise HTTPException(status_code=409,
                            detail="A simulation is already running. Wait for it to finish.")
    t = Thread(target=_run_demo, daemon=True)
    t.start()
    return {"status": "started",
            "message": "Attack simulation started. Alerts will appear within 15–30 seconds.",
            "phases": ["DDoS SYN flood", "Port scan reconnaissance", "DGA / DNS tunnelling",
                       "Encrypted malware traffic", "C2 beaconing", "Data exfiltration"]}


@app.get("/api/demo/status")
async def demo_status():
    """Poll the current state of the running simulation."""
    return {
        "running":    demo_state["running"],
        "phase":      demo_state["phase"],
        "progress":   demo_state["progress"],
        "started_at": demo_state["started_at"],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
