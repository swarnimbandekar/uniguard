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

        # ── Phase 1: DDoS SYN flood ────────────────────────────────────
        # Mixed sources, varied packet sizes, not all to the same port
        demo_state["phase"] = "DDoS SYN flood"
        logger.info("[DEMO] Phase 1 – DDoS SYN flood")
        targets = ["192.168.1.100", "192.168.1.101", "10.0.0.5"]
        for i in range(4000):
            src = f"{random.randint(1,223)}.{random.randint(0,255)}." \
                  f"{random.randint(0,255)}.{random.randint(1,254)}"
            dst = random.choice(targets)
            port = random.choice([80, 443, 8080])
            sz = random.randint(54, 78)
            _send(p, _make_pkt(src, dst, random.randint(1024, 65535), port,
                               pkt_len=sz, payload_len=0, tcp_flags=syn))
            if i % 1000 == 999:
                p.flush()
                demo_state["progress"] = int((i + 1) / 4000 * 20)
        p.flush()
        demo_state["progress"] = 20

        # ── Phase 2: Port scan ─────────────────────────────────────────
        # Varied scanner, partial RST responses, randomised port order
        demo_state["phase"] = "Port scan reconnaissance"
        logger.info("[DEMO] Phase 2 – Port scan")
        scanners = ["10.10.10.10", "172.16.0.99"]
        target  = "192.168.1.200"
        ports = list(range(1, 501))
        random.shuffle(ports)
        for i, port in enumerate(ports):
            scanner = random.choice(scanners)
            _send(p, _make_pkt(scanner, target,
                               random.randint(40000, 60000), port,
                               pkt_len=random.randint(54, 66), payload_len=0, tcp_flags=syn))
            if random.random() < 0.92:
                _send(p, _make_pkt(target, scanner, port,
                                   random.randint(40000, 60000),
                                   pkt_len=54, payload_len=0, tcp_flags=rst))
            if i % 100 == 99:
                p.flush()
                demo_state["progress"] = 20 + int((i + 1) / 500 * 17)
        p.flush()
        demo_state["progress"] = 37

        # ── Phase 3: DGA / DNS tunnelling ──────────────────────────────
        # Realistic entropy mix — some short, some long random domains
        demo_state["phase"] = "DGA / DNS tunnelling"
        logger.info("[DEMO] Phase 3 – DGA domains")
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        tlds  = [".com", ".net", ".org", ".info", ".xyz", ".top", ".click"]
        dga_hosts = ["192.168.1.50", "192.168.1.51"]
        for i in range(100):
            src = random.choice(dga_hosts)
            length = random.randint(10, 26)
            domain = "".join(random.choices(chars, k=length)) + random.choice(tlds)
            _send(p, _make_pkt(src, "8.8.8.8",
                               random.randint(1024, 65535), 53,
                               protocol=17,
                               pkt_len=random.randint(72, 95),
                               payload_len=random.randint(50, 70),
                               tcp_flags=None, dns_query=domain))
            if i % 25 == 24:
                p.flush()
                demo_state["progress"] = 37 + int((i + 1) / 100 * 13)
        p.flush()
        demo_state["progress"] = 50

        # ── Phase 4: Encrypted malware — non-standard port, long flow ──
        # fwd_bytes_per_conn >= 500, bytes_per_conn >= 700, psh_per_conn >= 3
        # Use completely fresh IPs not used elsewhere in the demo
        demo_state["phase"] = "Encrypted malware traffic"
        logger.info("[DEMO] Phase 4 – Encrypted malware")
        enc_pairs = [
            ("10.20.30.40", "91.230.14.11",   4444),
            ("10.20.30.41", "185.220.101.55",  7788),
            ("10.20.30.42", "94.102.49.190",   6667),
        ]
        base_ts = int(time.time() * 1_000_000)
        for enc_src, enc_dst, enc_port in enc_pairs:
            # One SYN to open the session
            syn_pkt = _make_pkt(enc_src, enc_dst,
                                random.randint(40000, 60000), enc_port,
                                pkt_len=60, payload_len=0, tcp_flags=syn)
            syn_pkt["timestamp_us"] = base_ts
            _send(p, syn_pkt)
            # 15 forward PSH packets (~80 bytes payload each) → fwd_bytes ≈ 1200
            sport = random.randint(40000, 60000)
            for i in range(15):
                offset_us = (i + 1) * 300_000   # 300ms apart → 4.5s span
                pkt = _make_pkt(enc_src, enc_dst, sport, enc_port,
                                pkt_len=random.randint(110, 150),
                                payload_len=random.randint(80, 120),
                                tcp_flags=psh)
                pkt["timestamp_us"] = base_ts + offset_us
                _send(p, pkt)
            # 6 backward PSH responses (~200 bytes) → bwd_bytes ≈ 1200
            for i in range(6):
                offset_us = (i + 1) * 700_000
                pkt = _make_pkt(enc_dst, enc_src, enc_port, sport,
                                pkt_len=random.randint(230, 270),
                                payload_len=random.randint(180, 220),
                                tcp_flags=psh)
                pkt["timestamp_us"] = base_ts + offset_us
                _send(p, pkt)
            p.flush()
        demo_state["progress"] = 63

        # ── Phase 5: C2 beaconing — SYN + data packets, 2s apart ──────
        # SYN recorded by c2_conn_events; PSH data for estab check
        # MIN_BEACONS_STRICT=5, intervals must be 1-900s, cv<0.5
        demo_state["phase"] = "C2 beaconing"
        logger.info("[DEMO] Phase 5 – C2 beaconing (spaced over ~16s)")
        c2_pairs = [
            ("10.30.40.50", "91.234.56.78",   9001),
            ("10.30.40.51", "45.142.212.100",  4443),
        ]
        beacon_interval = 2.0
        beacons_per_pair = 8
        base_ts_c2 = int(time.time() * 1_000_000)
        for beat in range(beacons_per_pair):
            for c2_src, c2_dst, c2_port in c2_pairs:
                offset_us = int(beat * beacon_interval * 1_000_000)
                sport = random.randint(49000, 55000)
                # SYN — this is what gets recorded by c2_conn_events
                syn_pkt = _make_pkt(c2_src, c2_dst, sport, c2_port,
                                    pkt_len=60, payload_len=0, tcp_flags=syn)
                syn_pkt["timestamp_us"] = base_ts_c2 + offset_us
                _send(p, syn_pkt)
                # PSH data packet (small outbound — beacon check-in)
                data_pkt = _make_pkt(c2_src, c2_dst, sport, c2_port,
                                     pkt_len=random.randint(110, 140),
                                     payload_len=random.randint(70, 100),
                                     tcp_flags=psh)
                data_pkt["timestamp_us"] = base_ts_c2 + offset_us + 20_000
                _send(p, data_pkt)
                # Inbound response (larger)
                resp_pkt = _make_pkt(c2_dst, c2_src, c2_port, sport,
                                     pkt_len=random.randint(350, 450),
                                     payload_len=random.randint(300, 400),
                                     tcp_flags=psh)
                resp_pkt["timestamp_us"] = base_ts_c2 + offset_us + 50_000
                _send(p, resp_pkt)
            p.flush()
            if beat < beacons_per_pair - 1:
                time.sleep(beacon_interval)
            demo_state["progress"] = 63 + int((beat + 1) / beacons_per_pair * 20)
        p.flush()
        demo_state["progress"] = 83

        # ── Phase 6: Data exfiltration ─────────────────────────────────
        # Large asymmetric upload: many big outbound, few tiny ACK responses
        demo_state["phase"] = "Data exfiltration"
        logger.info("[DEMO] Phase 6 – Data exfiltration")
        exf_pairs = [
            ("192.168.1.60", "185.100.200.50", 443),
            ("192.168.1.61", "104.21.90.77",   8443),
        ]
        for exf_src, exf_dst, exf_port in exf_pairs:
            _send(p, _make_pkt(exf_src, exf_dst, 51000, exf_port,
                               pkt_len=60, payload_len=0, tcp_flags=syn))
            for i in range(350):
                _send(p, _make_pkt(exf_src, exf_dst, 51000, exf_port,
                                   pkt_len=random.randint(1200, 1460),
                                   payload_len=random.randint(1100, 1400),
                                   tcp_flags=psh))
                if i % 100 == 99:
                    p.flush()
            for _ in range(4):
                _send(p, _make_pkt(exf_dst, exf_src, exf_port, 51000,
                                   pkt_len=60, payload_len=0, tcp_flags=ack))
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
