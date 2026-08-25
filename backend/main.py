"""
FastAPI Backend for Threat Detection Dashboard.
Consumes alerts from Kafka and streams them to the dashboard via WebSocket.
Provides REST endpoints for historical alerts and statistics.
"""

import asyncio
import json
import logging
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from threading import Thread
from typing import List, Optional

from confluent_kafka import Consumer, KafkaError
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
