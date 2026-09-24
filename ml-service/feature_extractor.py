"""
Feature Extraction Service.
Consumes raw packet records from Kafka, aggregates into flow-level features,
calls gRPC inference, and produces alerts to Kafka.

Port scan detection runs LOCALLY using the portscan module (no gRPC needed),
while DDoS and DGA detection use the gRPC inference server.
"""

import json
import logging
import math
import os
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock, Thread
from typing import Dict, List, Optional

import grpc
import numpy as np
from confluent_kafka import Consumer, KafkaError, Producer

import inference_pb2
import inference_pb2_grpc

# Port scan detection (local, no gRPC)
from portscan.model import PortScanDetector
from portscan.features import Flow, WindowSpec
from portscan.streaming import StreamingWindower, StreamStats

# Encrypted malware detection (local, flow-level, no gRPC)
from encrypted_malware.detector import EncryptedMalwareDetector

# DDoS detection (local, flow-level, no gRPC)
from ddos.detector import DDoSDetector

# Data exfiltration detection (local, flow-level, no gRPC)
from exfiltration.detector import ExfiltrationDetector

# C2 beaconing detection (local, periodicity analysis, no gRPC)
from c2beacon.detector import C2BeaconDetector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Configuration from environment
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:9092")
KAFKA_INPUT_TOPIC = os.environ.get("KAFKA_INPUT_TOPIC", "flow-records")
KAFKA_OUTPUT_TOPIC = os.environ.get("KAFKA_OUTPUT_TOPIC", "threat-alerts")
GRPC_INFERENCE_HOST = os.environ.get("GRPC_INFERENCE_HOST", "localhost:50051")
WINDOW_SECONDS = int(os.environ.get("WINDOW_SECONDS", "10"))
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.8"))
PORTSCAN_MODEL_PATH = Path(os.environ.get("PORTSCAN_MODEL_PATH", "/app/models/portscan-10s2s.joblib"))
ENCRYPTED_MALWARE_MODEL_PATH = Path(os.environ.get("ENCRYPTED_MALWARE_MODEL_PATH", "/app/models/encrypted_malware_flow.joblib"))
DDOS_MODEL_PATH = Path(os.environ.get("DDOS_MODEL_PATH", "/app/models/ddos_flow.joblib"))
EXFILTRATION_MODEL_PATH = Path(os.environ.get("EXFILTRATION_MODEL_PATH", "/app/models/exfiltration_flow.joblib"))
C2_MODEL_PATH = Path(os.environ.get("C2_MODEL_PATH", "/app/models/c2_detector_60s_10s_ext13.joblib"))  # STANDBY
C2_INTERNAL_PREFIXES = os.environ.get("C2_INTERNAL_PREFIXES", "")  # STANDBY

# Well-known service ports excluded from C2 beacon consideration (a covert C2
# channel does not phone home over web/mail/SSH/etc.). Shared by the packet-level
# connection recorder and the window-boundary beacon scorer.
_C2_STD_PORTS = {80, 443, 22, 25, 53, 110, 143, 993, 995, 3389,
                 8080, 8443, 445, 139, 135}


@dataclass
class FlowState:
    """Tracks per-flow state for feature computation."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start_time: float = 0.0
    last_time: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_iats: list = field(default_factory=list)
    bwd_iats: list = field(default_factory=list)
    fwd_pkt_sizes: list = field(default_factory=list)
    bwd_pkt_sizes: list = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    psh_count: int = 0
    last_fwd_time: float = 0.0
    last_bwd_time: float = 0.0


@dataclass
class SourceIPState:
    """Tracks per-source-IP state for port scan detection."""
    dst_ports: set = field(default_factory=set)
    dst_ips: set = field(default_factory=set)
    flow_count: int = 0
    syn_count: int = 0
    total_packets: int = 0
    rst_count: int = 0
    pkt_sizes: list = field(default_factory=list)
    flow_durations: list = field(default_factory=list)


class FeatureExtractor:
    def __init__(self):
        self.flows: Dict[str, FlowState] = {}
        self.source_ips: Dict[str, SourceIPState] = defaultdict(SourceIPState)
        self.dns_queries: List[dict] = []
        # Accurate per-connection start times for C2 beacon periodicity, captured
        # at the packet level from the initiating SYN. The flow table merges
        # connections that reuse an ephemeral source port within a window, which
        # destroys the true inter-connection spacing a beacon detector needs; this
        # SYN-driven record preserves one timestamp per real connection attempt.
        # Keyed by (src_ip, dst_ip, dst_port) -> list[float ts]. Drained each window.
        self.c2_conn_events: Dict[tuple, list] = defaultdict(list)
        # Per-window cross-detector suppression: destination endpoints already
        # claimed by DDoS or PortScan this window are excluded from C2 beacon
        # scoring, so a flood/scan can't ALSO be mislabelled as beaconing.
        self.window_claimed_dsts: set = set()
        # Sources flagged as scanners this window — also excluded from C2 beacon.
        self.window_claimed_srcs: set = set()
        self.lock = Lock()
        self.window_start = time.time()

        # Kafka consumer
        self.consumer = Consumer({
            "bootstrap.servers": KAFKA_BROKER,
            "group.id": "feature-extractor-group",
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
            "session.timeout.ms": 30000,
        })
        self.consumer.subscribe([KAFKA_INPUT_TOPIC])

        # Kafka producer
        self.producer = Producer({
            "bootstrap.servers": KAFKA_BROKER,
            "client.id": "alert-producer",
            "acks": "all",
        })

        # gRPC client
        self.grpc_channel = grpc.insecure_channel(GRPC_INFERENCE_HOST)
        self.grpc_stub = inference_pb2_grpc.ThreatDetectorStub(self.grpc_channel)

        # PortScan detection (local model, no gRPC)
        self.portscan_detector = None
        self.portscan_windower = None
        self._open_tcp_flows: Dict[str, dict] = {}  # For conn_state approximation
        self._load_portscan_model()

        # Encrypted malware detection (local, flow-level, no gRPC)
        self.encrypted_malware_detector: Optional[EncryptedMalwareDetector] = None
        self._load_encrypted_malware_model()

        # DDoS detection (local, flow-level, no gRPC)
        self.ddos_detector: Optional[DDoSDetector] = None
        self._load_ddos_model()

        # Data exfiltration detection (local, flow-level, no gRPC)
        self.exfiltration_detector: Optional[ExfiltrationDetector] = None
        self._load_exfiltration_model()

        # C2 beaconing detection (local, periodicity analysis, no gRPC)
        self.c2_beacon_detector = C2BeaconDetector()

        logger.info(f"Feature extractor initialized")
        logger.info(f"  Kafka broker: {KAFKA_BROKER}")
        logger.info(f"  Input topic: {KAFKA_INPUT_TOPIC}")
        logger.info(f"  Output topic: {KAFKA_OUTPUT_TOPIC}")
        logger.info(f"  gRPC server: {GRPC_INFERENCE_HOST}")
        logger.info(f"  Window: {WINDOW_SECONDS}s, Threshold: {CONFIDENCE_THRESHOLD}")
        if self.portscan_detector:
            logger.info(f"  PortScan model: {PORTSCAN_MODEL_PATH.name} (local)")
        else:
            logger.warning("  PortScan model: NOT LOADED")
        if self.encrypted_malware_detector:
            logger.info(f"  Encrypted Malware model: {ENCRYPTED_MALWARE_MODEL_PATH.name} (local)")
        else:
            logger.warning("  Encrypted Malware model: NOT LOADED")
        if self.ddos_detector:
            logger.info(f"  DDoS model: {DDOS_MODEL_PATH.name} (local)")
        else:
            logger.warning("  DDoS model: NOT LOADED")
        if self.exfiltration_detector:
            logger.info(f"  Exfiltration model: {EXFILTRATION_MODEL_PATH.name} (local)")
        else:
            logger.warning("  Exfiltration model: NOT LOADED")
        logger.info(f"  C2 Beacon detector: periodicity analysis (local)")

    def _load_portscan_model(self):
        """Load the portscan model and initialize the streaming windower."""
        try:
            if PORTSCAN_MODEL_PATH.exists():
                self.portscan_detector = PortScanDetector.load(
                    PORTSCAN_MODEL_PATH, allow_version_mismatch=True
                )
                self.portscan_windower = StreamingWindower(
                    spec=self.portscan_detector.window_spec,
                    lateness_seconds=3.0,
                    stats=StreamStats(),
                )
                logger.info(f"Loaded PortScan model: {self.portscan_detector.model_name}")
                logger.info(f"  Window: {self.portscan_detector.window_spec.window_seconds}s, "
                            f"stride: {self.portscan_detector.window_spec.stride_seconds}s")
                logger.info(f"  Threshold: {self.portscan_detector.threshold:.4f}")
            else:
                logger.warning(f"PortScan model not found at {PORTSCAN_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to load PortScan model: {e}")

    def _load_encrypted_malware_model(self):
        """Load the encrypted malware flow detection model."""
        try:
            if ENCRYPTED_MALWARE_MODEL_PATH.exists():
                self.encrypted_malware_detector = EncryptedMalwareDetector(ENCRYPTED_MALWARE_MODEL_PATH)
            else:
                logger.warning(f"Encrypted malware model not found at {ENCRYPTED_MALWARE_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to load encrypted malware model: {e}")

    def _load_ddos_model(self):
        """Load the DDoS flow detection model."""
        try:
            if DDOS_MODEL_PATH.exists():
                self.ddos_detector = DDoSDetector(DDOS_MODEL_PATH)
            else:
                logger.warning(f"DDoS model not found at {DDOS_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to load DDoS model: {e}")

    def _load_exfiltration_model(self):
        """Load the data exfiltration detection model."""
        try:
            if EXFILTRATION_MODEL_PATH.exists():
                self.exfiltration_detector = ExfiltrationDetector(EXFILTRATION_MODEL_PATH)
            else:
                logger.warning(f"Exfiltration model not found at {EXFILTRATION_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to load exfiltration model: {e}")

    def _score_encrypted_malware(self):
        """
        Score all mature TCP flows for encrypted malware behavior.
        Called at window boundaries. Uses only flow-level metadata —
        no TLS parsing, no payload decryption.
        """
        if self.encrypted_malware_detector is None:
            return

        alerts_produced = 0

        # --- Repeated encrypted-session pattern (runs before C2) --------------
        # An encrypted-malware channel opens repeated sessions to a non-standard
        # port, each carrying a real (encrypted-looking) DATA exchange: several
        # PSH data packets and hundreds of payload bytes per session. A C2 beacon,
        # by contrast, is a tiny uniform check-in (a packet or two, tens of bytes).
        # Both are periodic on non-std ports, so per-flow scoring alone cannot tell
        # them apart. Here we aggregate per endpoint and, when the repeated-session
        # DATA signature is present, emit EncryptedMalware and CLAIM the endpoint
        # so the C2 scorer skips it — keeping each attack in its own alert class.
        C2_STD = _C2_STD_PORTS
        with self.lock:
            em_agg = {}  # (src,dst,dport) -> aggregate session stats
            for key, flow in self.flows.items():
                if flow.protocol != 6 or flow.dst_port in C2_STD or flow.dst_port <= 1024:
                    continue
                if flow.bwd_packets == 0:  # never established
                    continue
                a = em_agg.setdefault((flow.src_ip, flow.dst_ip, flow.dst_port), {
                    "sessions": 0, "bytes": 0, "fwd_bytes": 0, "psh": 0, "pkts": 0,
                })
                a["sessions"] += 1
                a["bytes"] += flow.fwd_bytes + flow.bwd_bytes
                a["fwd_bytes"] += flow.fwd_bytes
                a["psh"] += flow.psh_count
                a["pkts"] += flow.fwd_packets + flow.bwd_packets

            for (src_ip, dst_ip, dport), a in em_agg.items():
                if a["sessions"] < 3:
                    continue
                bytes_per_conn = a["bytes"] / a["sessions"]
                fwd_bytes_per_conn = a["fwd_bytes"] / a["sessions"]
                psh_per_conn = a["psh"] / a["sessions"]
                # Encrypted-malware session signature: each session carries a real
                # data exchange — a substantial OUTBOUND (client->server) payload
                # of several hundred ciphertext bytes across multiple PSH data
                # packets. Gating on OUTBOUND bytes (not total) is what separates
                # this from a C2 beacon: a beacon's outbound check-in is tiny
                # (~tens of bytes) even if the server echoes a large banner back,
                # so a beacon can never satisfy fwd_bytes_per_conn >= 500. Tiny
                # beacons are therefore left entirely to the C2 detector.
                if fwd_bytes_per_conn >= 500 and bytes_per_conn >= 700 and psh_per_conn >= 3:
                    score = 0.90
                    severity = self.encrypted_malware_detector.severity(score)
                    alert = self._create_alert(
                        threat_class="EncryptedMalware",
                        confidence=score,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=0,
                        dst_port=dport,
                        evidence={
                            "session_count": a["sessions"],
                            "bytes_per_session": round(bytes_per_conn, 1),
                            "fwd_bytes_per_session": round(fwd_bytes_per_conn, 1),
                            "psh_per_session": round(psh_per_conn, 1),
                            "total_bytes": a["bytes"],
                            "dst_port": dport,
                        },
                    )
                    self._produce_alert(alert)
                    alerts_produced += 1
                    # Claim so the C2 beacon scorer skips this endpoint.
                    self.window_claimed_dsts.add(dst_ip)
                    logger.info(
                        f"EncryptedMalware alert (repeated session): {src_ip}->"
                        f"{dst_ip}:{dport} sessions={a['sessions']} "
                        f"bytes/conn={bytes_per_conn:.0f} psh/conn={psh_per_conn:.1f}"
                    )

        with self.lock:
            for key, flow in self.flows.items():
                # Only score TCP flows with enough data
                if flow.protocol != 6:
                    continue
                total_pkts = flow.fwd_packets + flow.bwd_packets
                if total_pkts < 3:
                    continue

                # Score the flow
                score = self.encrypted_malware_detector.score(flow)
                if score is None:
                    continue

                if self.encrypted_malware_detector.is_malware(score):
                    severity = self.encrypted_malware_detector.severity(score)
                    duration = max(flow.last_time - flow.start_time, 0.001)
                    alert = self._create_alert(
                        threat_class="EncryptedMalware",
                        confidence=score,
                        severity=severity,
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        src_port=flow.src_port,
                        dst_port=flow.dst_port,
                        evidence={
                            "duration_sec": round(duration, 2),
                            "fwd_bytes": flow.fwd_bytes,
                            "bwd_bytes": flow.bwd_bytes,
                            "fwd_packets": flow.fwd_packets,
                            "bwd_packets": flow.bwd_packets,
                            "bytes_per_sec": round((flow.fwd_bytes + flow.bwd_bytes) / duration, 1),
                            "dst_port": flow.dst_port,
                            "down_up_ratio": round(flow.bwd_bytes / max(flow.fwd_bytes, 1), 2),
                        },
                    )
                    self._produce_alert(alert)
                    alerts_produced += 1
                    logger.info(
                        f"EncryptedMalware alert: {flow.src_ip}:{flow.src_port}→"
                        f"{flow.dst_ip}:{flow.dst_port} score={score:.3f} sev={severity}"
                    )

        if alerts_produced > 0:
            logger.info(f"Encrypted malware scan: {alerts_produced} alerts")

    def _score_ddos(self):
        """
        Score flows for DDoS attack patterns.
        Called at window boundaries.
        Only flags HIGH-VOLUME flows that actually look like floods.
        """
        if self.ddos_detector is None:
            return

        alerts_produced = 0

        with self.lock:
            # --- Aggregate flows by destination to detect volumetric floods ---
            # A DDoS is characterized by MANY connections/packets hammering one
            # victim within the window, not a single flow. We aggregate per dst.
            dst_agg = {}  # dst_ip -> {pkts, bytes, flows, syn, first_ts, last_ts, dst_port}
            for key, flow in self.flows.items():
                if flow.protocol != 6:
                    continue
                d = dst_agg.setdefault(flow.dst_ip, {
                    "pkts": 0, "bytes": 0, "flows": 0, "syn": 0,
                    "first_ts": flow.start_time, "last_ts": flow.last_time,
                    "dst_port": flow.dst_port, "src_ip": flow.src_ip,
                    "dst_ports": set(), "resp_pkts": 0,
                })
                d["pkts"] += flow.fwd_packets + flow.bwd_packets
                d["bytes"] += flow.fwd_bytes + flow.bwd_bytes
                d["flows"] += 1
                d["syn"] += flow.syn_count
                d["dst_ports"].add(flow.dst_port)
                d["resp_pkts"] += flow.bwd_packets
                d["first_ts"] = min(d["first_ts"], flow.start_time)
                d["last_ts"] = max(d["last_ts"], flow.last_time)

            for dst_ip, d in dst_agg.items():
                duration = max(d["last_ts"] - d["first_ts"], 0.001)
                pkt_rate = d["pkts"] / duration

                # --- Port-scan exclusion -------------------------------------
                # A port scan also produces "many short connections to one host
                # quickly", but its signature is fan-out across MANY distinct
                # destination ports with near-zero payload. A volumetric/
                # connection flood instead concentrates on ONE (or a few) ports
                # and moves real volume. Skip the scan pattern so it is left for
                # the PortScan detector instead of being mislabelled as DDoS.
                unique_dports = len(d["dst_ports"])
                # Broad destination-port fan-out from one source to one host is
                # the defining signature of a port scan, whether the scanned
                # ports are closed (tiny SYN/RST probes) or open (they reply with
                # data). A volumetric flood, by contrast, concentrates on one or a
                # few service ports. So fan-out ALONE is decisive here — do not
                # also require tiny packets / no responses, since scanning a host
                # with many OPEN ports (e.g. Metasploitable) produces real replies
                # and would otherwise slip through and be mislabelled DDoS.
                looks_like_scan = unique_dports >= 20
                if looks_like_scan:
                    # Claim the scanner source so C2 beacon scoring also skips it.
                    self.window_claimed_srcs.add(d["src_ip"])
                    continue

                # --- Data-exfiltration exclusion -----------------------------
                # A single high-throughput connection with a strongly asymmetric
                # UPLOAD is exfiltration, not a volumetric DDoS. A real flood is
                # made of MANY connections (or sources) hammering a victim; one
                # fat upload flow is the exfil detector's job. Without this, a
                # bulk upload trips the "sustained high rate" branch below and
                # gets double-labelled DDoS + DataExfiltration.
                fwd = sum(f.fwd_bytes for f in self.flows.values()
                          if f.dst_ip == dst_ip and f.protocol == 6)
                bwd = sum(f.bwd_bytes for f in self.flows.values()
                          if f.dst_ip == dst_ip and f.protocol == 6)
                asymmetric_upload = fwd > 100_000 and fwd > 4 * max(bwd, 1)
                if d["flows"] <= 3 and asymmetric_upload:
                    continue

                # Volumetric DDoS signature: high aggregate packet rate from a
                # flood of MANY connections, OR a connection flood to one victim
                # in a short time. Require multiple connections so a single fat
                # flow (bulk download/upload) is not mistaken for a flood, and
                # keep it concentrated on a few ports (a flood hammers a service;
                # a scan sprays ports).
                is_flood = (
                    (d["pkts"] >= 500 and pkt_rate >= 200 and d["flows"] >= 10)  # sustained high-rate flood
                    or (d["flows"] >= 200 and duration < 15 and unique_dports <= 5)  # connection flood on few ports
                )
                if not is_flood:
                    continue

                # Confidence scales with intensity
                score = min(0.90 + min(pkt_rate / 5000, 0.09), 0.99)
                if d["flows"] >= 500 or pkt_rate >= 2000:
                    score = 0.99

                # Claim this victim so C2 beacon scoring skips the flood traffic.
                self.window_claimed_dsts.add(dst_ip)

                severity = "CRITICAL" if score >= 0.97 else "HIGH" if score >= 0.93 else "MEDIUM"
                if True:
                    total_bytes = d["bytes"]
                    alert = self._create_alert(
                        threat_class="DDoS",
                        confidence=score,
                        severity=severity,
                        src_ip=d["src_ip"],
                        dst_ip=dst_ip,
                        src_port=0,
                        dst_port=d["dst_port"],
                        evidence={
                            "duration_sec": round(duration, 2),
                            "total_bytes": d["bytes"],
                            "total_packets": d["pkts"],
                            "connection_count": d["flows"],
                            "bytes_per_sec": round(d["bytes"] / duration, 1),
                            "pkts_per_sec": round(pkt_rate, 1),
                            "syn_count": d["syn"],
                        },
                    )
                    self._produce_alert(alert)
                    alerts_produced += 1
                    logger.info(
                        f"DDoS alert: {d['src_ip']}→{dst_ip}:{d['dst_port']} "
                        f"score={score:.3f} sev={severity} pkts/s={pkt_rate:.0f} "
                        f"conns={d['flows']}"
                    )

        if alerts_produced > 0:
            logger.info(f"DDoS scan: {alerts_produced} alerts")

    def _score_exfiltration(self):
        """
        Score flows for data exfiltration patterns.
        Called at window boundaries.
        """
        if self.exfiltration_detector is None:
            return

        alerts_produced = 0

        with self.lock:
            for key, flow in self.flows.items():
                if flow.protocol != 6:
                    continue
                if flow.fwd_bytes < 1000:
                    continue

                score = self.exfiltration_detector.score(flow)
                if score is None:
                    continue

                if self.exfiltration_detector.is_exfiltration(score):
                    severity = self.exfiltration_detector.severity(score)
                    duration = max(flow.last_time - flow.start_time, 0.001)
                    alert = self._create_alert(
                        threat_class="DataExfiltration",
                        confidence=score,
                        severity=severity,
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        src_port=flow.src_port,
                        dst_port=flow.dst_port,
                        evidence={
                            "duration_sec": round(duration, 2),
                            "fwd_bytes": flow.fwd_bytes,
                            "bwd_bytes": flow.bwd_bytes,
                            "up_down_ratio": round(flow.fwd_bytes / max(flow.bwd_bytes, 1), 2),
                            "fwd_packets": flow.fwd_packets,
                            "bwd_packets": flow.bwd_packets,
                            "response_ratio": round(flow.bwd_packets / max(flow.fwd_packets, 1), 3),
                            "bytes_per_sec": round((flow.fwd_bytes + flow.bwd_bytes) / duration, 1),
                        },
                    )
                    self._produce_alert(alert)
                    alerts_produced += 1
                    logger.info(
                        f"Exfiltration alert: {flow.src_ip}→{flow.dst_ip}:{flow.dst_port} "
                        f"score={score:.3f} sev={severity} upload={flow.fwd_bytes}"
                    )

        if alerts_produced > 0:
            logger.info(f"Exfiltration scan: {alerts_produced} alerts")

    def _score_c2_beacon(self):
        """
        Feed current window's flows into the C2 beacon tracker, then scan
        for periodic beaconing patterns across the rolling history.
        """
        if self.c2_beacon_detector is None:
            return

        # Well-known service ports: legitimate repeated connections here (web,
        # mail, SSH, etc.) are not what a covert C2 channel uses. Real beacons
        # favour non-standard/high ports.
        C2_SKIP_PORTS = {80, 443, 22, 25, 53, 110, 143, 993, 995, 3389,
                         8080, 8443, 445, 139, 135}
        # A genuine beacon completes a session and exchanges a small but non-zero
        # payload. Floods and scans send SYN-only / near-zero-byte probes.
        MIN_BYTES_PER_CONN = 40

        with self.lock:
            claimed_dsts = set(self.window_claimed_dsts)
            claimed_srcs = set(self.window_claimed_srcs)

            # Build a per-endpoint summary from this window's flows, used to
            # QUALIFY an endpoint (established, byte-carrying, non-std port,
            # low-rate). The actual beacon TIMESTAMPS come from the packet-level
            # SYN recorder (self.c2_conn_events), which preserves one timestamp
            # per real connection — the flow table merges source-port reuse and
            # would otherwise collapse ~6 beacons/window into 1-2 events and
            # inflate the measured interval.
            endpoint = {}  # (src,dst,dport) -> {resp, bytes, total_pkts, dur, avg_bytes}
            for key, flow in self.flows.items():
                if flow.protocol != 6:
                    continue
                ek = (flow.src_ip, flow.dst_ip, flow.dst_port)
                e = endpoint.setdefault(ek, {"resp": 0, "bytes": 0, "pkts": 0,
                                             "dur": 0.0, "flows": 0,
                                             "estab": 0, "rst": 0, "data_bytes": 0})
                e["resp"] += flow.bwd_packets
                e["bytes"] += flow.fwd_bytes + flow.bwd_bytes
                e["pkts"] += flow.fwd_packets + flow.bwd_packets
                e["dur"] += max(flow.last_time - flow.start_time, 0.0)
                e["flows"] += 1
                e["rst"] += flow.rst_count
                # An ESTABLISHED beacon connection exchanges data beyond the
                # 3-way handshake: it carries a PSH data packet in at least one
                # direction. A connection to a CLOSED port is SYN -> RST with no
                # data (psh_count == 0), which must NOT count as a beacon check-in.
                if flow.psh_count > 0 and flow.bwd_packets > 0:
                    e["estab"] += 1
                    e["data_bytes"] += flow.fwd_bytes + flow.bwd_bytes

            # Drain the accurate per-connection SYN timestamps for this window.
            conn_events = {k: sorted(v) for k, v in self.c2_conn_events.items()}
            self.c2_conn_events = defaultdict(list)

            for ek, times in conn_events.items():
                src_ip, dst_ip, dst_port = ek

                # --- Cross-detector suppression -------------------------------
                # A flood/scan destination or a flagged scanner source is never a
                # beacon. This guard is correct and cheap, so it stays a hard gate.
                if dst_ip in claimed_dsts or src_ip in claimed_srcs:
                    continue

                # --- Well-known service port guard ----------------------------
                # Covert C2 does not phone home over web/mail/SSH/etc.
                if dst_port in C2_SKIP_PORTS:
                    continue

                # --- Window flow summary (may be absent for a slow beacon) ----
                # A real beacon checks in every 30s-few minutes, but self.flows is
                # reset every WINDOW_SECONDS (10s). So on most windows a slow
                # beacon has NO flow summary here — that is EXPECTED and must not
                # cause us to throw the connection timestamp away. Previously
                # `if e is None: continue` silently dropped every check-in that
                # didn't land a complete, data-carrying flow inside the same 10s
                # window, so a slow beacon's timestamps never accumulated and it
                # could never reach the beacon-count threshold. We now ALWAYS
                # record the timestamp; the quality guards below only apply when
                # we actually have this window's flow data, and an obvious
                # flood/scan burst is still rejected.
                e = endpoint.get(ek)

                if e is not None:
                    # --- Flood/scan burst guard (only when we have flow data) --
                    # A beacon is low-and-slow: each check-in is a light session.
                    # A burst of many packets on a single connection is a
                    # flood/scan, not a beacon — skip recording it.
                    if e["flows"] and (e["pkts"] / e["flows"]) > 60:
                        continue
                    # A destination that only ever RSTs (closed port, SYN->RST,
                    # no data at all across every observed flow) is not a beacon
                    # target. Only reject when we have flow data AND none of it
                    # established — otherwise we keep the timestamp.
                    if e["flows"] > 0 and e["estab"] == 0 and e["data_bytes"] == 0:
                        continue
                    per_conn_bytes = e["bytes"] / max(len(times), 1)
                else:
                    # No flow summary this window (slow beacon between windows):
                    # attribute a nominal small payload; the detector's
                    # MIN_TOTAL_BYTES guard still requires real accumulated bytes
                    # over the beacon's lifetime before it fires.
                    per_conn_bytes = MIN_BYTES_PER_CONN

                logger.info(
                    "C2 DEBUG cand: %s->%s:%s conn_events=%d flow_data=%s "
                    "estab=%s data_bytes=%s",
                    src_ip, dst_ip, dst_port, len(times),
                    e is not None,
                    (e["estab"] if e else "-"),
                    (e["data_bytes"] if e else "-"),
                )
                for ts in times:
                    self.c2_beacon_detector.observe(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        ts=ts,
                        nbytes=int(per_conn_bytes),
                    )

            detections = self.c2_beacon_detector.scan()

        alerts_produced = 0
        for src_ip, dst_ip, dst_port, ev in detections:
            confidence = ev["confidence"]
            if not self.c2_beacon_detector.is_beacon(confidence):
                continue
            severity = self.c2_beacon_detector.severity(confidence)
            alert = self._create_alert(
                threat_class="C2_BEACONING",
                confidence=confidence,
                severity=severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=0,
                dst_port=dst_port,
                evidence={
                    "beacon_count": ev["beacon_count"],
                    "mean_interval_sec": ev["mean_interval_sec"],
                    "jitter_cv": ev["jitter_cv"],
                    "interval_std_sec": ev["interval_std_sec"],
                    "total_bytes": ev["total_bytes"],
                },
            )
            self._produce_alert(alert)
            alerts_produced += 1
            logger.info(
                f"C2Beacon alert: {src_ip}->{dst_ip}:{dst_port} "
                f"conf={confidence:.3f} interval={ev['mean_interval_sec']}s "
                f"jitter_cv={ev['jitter_cv']} beacons={ev['beacon_count']}"
            )

        if alerts_produced > 0:
            logger.info(f"C2 beacon scan: {alerts_produced} alerts")

    def _process_portscan_packet(self, pkt: dict):
        """Track TCP/UDP packets for portscan detection.
        
        Approximates Zeek conn_state from TCP flags, then feeds completed flows
        into the StreamingWindower for the calibrated portscan model.
        """
        if self.portscan_detector is None:
            return

        # Only process TCP and UDP (proto 6 and 17)
        proto = pkt.get("protocol", 0)
        if proto not in (6, 17):
            return

        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        dst_port = str(pkt["dst_port"])
        ts = pkt["timestamp_us"] / 1_000_000.0
        flags = pkt.get("tcp_flags") or {}

        # Skip broadcast/multicast source IPs — not real scan sources
        if (src_ip.endswith(".255") or src_ip.endswith(".0")
                or src_ip.startswith("224.") or src_ip.startswith("239.")
                or src_ip == "255.255.255.255"
                or src_ip.startswith("162.159.")    # Cloudflare WARP/DNS
                or src_ip.startswith("127.")        # Loopback
                or src_ip.startswith("104.16.")     # Cloudflare CDN
                ):
            return

        # For UDP: emit a flow immediately (stateless)
        if proto == 17:
            # Skip SERVER RESPONSES: a packet whose SOURCE port is a well-known
            # service port (e.g. DNS :53) is a reply to a client, not a scan.
            # Without this, a DNS server answering many ephemeral client ports
            # looks like it is "scanning" those ports and trips a false PortScan.
            src_port_int = pkt.get("src_port", 0)
            if src_port_int in _C2_STD_PORTS or src_port_int == 53:
                return
            flow = Flow(
                ts=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                conn_state="SF",  # UDP with a response would be SF; assume S0 for one-way
                duration=0.0,
                orig_pkts=1.0,
                resp_pkts=0.0,
                history="-",
            )
            self._emit_portscan_flow(flow)
            return

        # --- C2 beacon connection-start capture (packet level) ----------------
        # Record the initiating SYN (SYN set, ACK clear) of each TCP connection
        # to a non-standard/high port. This gives the C2 detector the TRUE start
        # time of every individual connection, independent of the flow table's
        # source-port-reuse merging, so beacon intervals are measured accurately.
        if flags.get("syn") and not flags.get("ack"):
            dport_int = pkt["dst_port"]
            if dport_int > 1024 and dport_int not in _C2_STD_PORTS:
                with self.lock:
                    self.c2_conn_events[(src_ip, dst_ip, dport_int)].append(ts)

        # A port scan is measured by a SOURCE hitting many distinct DESTINATION
        # ports. A busy server replying to many ephemeral client ports (e.g. the
        # victim of a DDoS/HTTP flood answering ~1000 client sockets from :80)
        # would otherwise look like that server "scanning" the client's ports.
        # A packet FROM a well-known service port TO a high ephemeral port that
        # is NOT an initiating SYN is a server reply, so it must never CREATE a
        # new scanner record. It may still update an existing peer (below), which
        # is what marks the real initiator's connection as established.
        src_port_int = pkt.get("src_port", 0)
        dst_port_int = pkt.get("dst_port", 0)
        is_initiating_syn = flags.get("syn", False) and not flags.get("ack", False)
        is_server_reply = (not is_initiating_syn
                           and (src_port_int in _C2_STD_PORTS or src_port_int < 1024)
                           and dst_port_int > 1024)

        # TCP: track connection state to approximate conn_state
        # Use directional key (src -> dst:port)
        tcp_key = f"{src_ip}->{dst_ip}:{dst_port}"
        reverse_key = f"{dst_ip}->{src_ip}:{pkt['src_port']}"

        with self.lock:
            record = self._open_tcp_flows.get(tcp_key)

            if record is None and is_server_reply:
                # Server reply with no existing initiator record: update the peer
                # (the real client's outbound flow) if present, but do NOT create
                # a spurious server-as-scanner record.
                peer = self._open_tcp_flows.get(reverse_key)
                if peer is not None:
                    peer["resp_pkts"] += 1.0
                    if flags.get("syn") and flags.get("ack"):
                        peer["syn_ack"] = True
                return

            if record is None:
                # New connection
                record = {
                    "first_ts": ts,
                    "last_ts": ts,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "orig_pkts": 1.0,
                    "resp_pkts": 0.0,
                    "syn": flags.get("syn", False),
                    "syn_ack": False,
                    "rst": flags.get("rst", False),
                    "fin": flags.get("fin", False),
                }
                self._open_tcp_flows[tcp_key] = record
            else:
                record["last_ts"] = ts
                record["orig_pkts"] += 1.0
                record["syn"] |= flags.get("syn", False)
                record["rst"] |= flags.get("rst", False)
                record["fin"] |= flags.get("fin", False)

            # Check if this is a response to an existing outbound connection
            peer = self._open_tcp_flows.get(reverse_key)
            if peer is not None:
                peer["resp_pkts"] += 1.0
                if flags.get("syn") and flags.get("ack"):
                    peer["syn_ack"] = True

            # Emit flow on RST or FIN (connection decided)
            if flags.get("rst") or flags.get("fin"):
                if record:
                    self._emit_tcp_flow(tcp_key, record)
                    self._open_tcp_flows.pop(tcp_key, None)

        # Periodic cleanup: emit stale flows (older than 30s with no activity)
        self._cleanup_stale_tcp_flows(ts)

    def _emit_tcp_flow(self, key: str, record: dict):
        """Convert a tracked TCP connection into a Flow and feed to windower."""
        established = record["syn_ack"] or record["resp_pkts"] > 0

        if record["syn"] and not established:
            state = "REJ" if record["rst"] else "S0"
        elif established and record["rst"]:
            state = "RSTO"
        elif established and record["fin"]:
            state = "SF"
        elif established:
            state = "OTH"
        else:
            state = "OTH"

        # History: "S" only for a lone SYN with no response
        history = "S" if state == "S0" and record["orig_pkts"] == 1 else "-"

        flow = Flow(
            ts=record["first_ts"],
            src_ip=record["src_ip"],
            dst_ip=record["dst_ip"],
            dst_port=record["dst_port"],
            conn_state=state,
            duration=max(0.0, record["last_ts"] - record["first_ts"]),
            orig_pkts=record["orig_pkts"],
            resp_pkts=record["resp_pkts"],
            history=history,
        )
        self._emit_portscan_flow(flow)

    def _emit_portscan_flow(self, flow: Flow):
        """Feed a flow to the streaming windower and produce alerts for any triggered windows."""
        windows = self.portscan_windower.push(flow)
        self._score_portscan_windows(windows)

    def _score_portscan_windows(self, windows):
        """Score windower-released windows and produce PortScan alerts.

        Shared by the push path (windows released as flows arrive) and the
        boundary tick path (windows released by wall-clock once traffic stops,
        so a scan burst that ends cleanly still gets scored).
        """
        for window in windows:
            # Must have multiple unique destination ports to be a real scan
            unique_ports = window.evidence.get("unique_dst_ports", 0)
            if unique_ports < 10:
                continue

            confidence = self.portscan_detector.score(window)
            # Use a higher threshold than the model's default (0.1989) to reduce
            # false positives on noisy/public networks. Only alert on strong signals.
            if confidence >= 0.60:
                severity = "CRITICAL" if confidence >= 0.98 else "HIGH" if confidence >= 0.90 else "MEDIUM" if confidence >= 0.80 else "LOW"
                alert = self._create_alert(
                    threat_class="PortScan",
                    confidence=confidence,
                    severity=severity,
                    src_ip=window.src_ip,
                    dst_ip="multiple",
                    src_port=0,
                    dst_port=0,
                    evidence={
                        "unique_dst_ports": window.evidence.get("unique_dst_ports", 0),
                        "unique_dst_hosts": window.evidence.get("unique_dst_hosts", 0),
                        "connection_attempts": window.evidence.get("connection_attempts", 0),
                        "failed_connections": window.evidence.get("failed_connections", 0),
                        "scan_rate": window.evidence.get("scan_rate", 0),
                    },
                )
                self._produce_alert(alert)
                # Claim this scanner so its regularly-paced probes are not also
                # scored as C2 beaconing.
                self.window_claimed_srcs.add(window.src_ip)
                logger.info(f"PortScan alert: src={window.src_ip}, conf={confidence:.3f}, "
                            f"ports={window.evidence.get('unique_dst_ports', 0)}")

    def _cleanup_stale_tcp_flows(self, current_ts: float):
        """Emit TCP flows that have been idle for > 5 seconds (SYN-only) or > 30s (others)."""
        stale_keys = []
        with self.lock:
            for key, record in self._open_tcp_flows.items():
                idle_time = current_ts - record["last_ts"]
                # SYN-only flows (no response) = likely scan probes, emit quickly
                if record["syn"] and not record["syn_ack"] and record["resp_pkts"] == 0:
                    if idle_time > 3.0:  # 3 seconds is enough for a scan probe
                        stale_keys.append(key)
                elif idle_time > 30.0:
                    stale_keys.append(key)
            for key in stale_keys:
                record = self._open_tcp_flows.pop(key)
                self._emit_tcp_flow(key, record)

    def _flush_open_scan_probes(self, current_ts: float):
        """At a window boundary, emit still-open TCP connection records into the
        portscan windower so a scan whose probes never got a RST/FIN (or whose
        burst just ended) still contributes its flows to a scorable window.

        Emits SYN-only / unestablished probes that are at least 1s old (the
        signature of a scan), plus any flow idle > 3s. Leaves fresh, still-active
        connections in place so genuine sessions aren't cut prematurely.
        """
        if self.portscan_detector is None:
            return
        emit_keys = []
        with self.lock:
            for key, record in self._open_tcp_flows.items():
                age = current_ts - record["first_ts"]
                idle = current_ts - record["last_ts"]
                unestablished = not record["syn_ack"] and record["resp_pkts"] == 0
                if (unestablished and age >= 1.0) or idle > 3.0:
                    emit_keys.append(key)
            emitted = [(k, self._open_tcp_flows.pop(k)) for k in emit_keys]
        # Emit outside the lock (_emit_portscan_flow pushes into the windower,
        # which is single-threaded here so this is safe and avoids re-entrancy).
        for key, record in emitted:
            self._emit_tcp_flow(key, record)

    def _flow_key(self, pkt: dict) -> str:
        """Generate flow key from packet (bidirectional)."""
        src = f"{pkt['src_ip']}:{pkt['src_port']}"
        dst = f"{pkt['dst_ip']}:{pkt['dst_port']}"
        proto = pkt["protocol"]
        if src < dst:
            return f"{src}-{dst}-{proto}"
        return f"{dst}-{src}-{proto}"

    def _is_forward(self, pkt: dict, flow: FlowState) -> bool:
        """Check if packet is in forward direction."""
        return pkt["src_ip"] == flow.src_ip and pkt["src_port"] == flow.src_port

    def _update_flow(self, pkt: dict):
        """Update flow state with new packet."""
        key = self._flow_key(pkt)
        ts = pkt["timestamp_us"] / 1_000_000.0  # Convert to seconds

        with self.lock:
            if key not in self.flows:
                self.flows[key] = FlowState(
                    src_ip=pkt["src_ip"],
                    dst_ip=pkt["dst_ip"],
                    src_port=pkt["src_port"],
                    dst_port=pkt["dst_port"],
                    protocol=pkt["protocol"],
                    start_time=ts,
                    last_time=ts,
                    last_fwd_time=ts,
                )

            flow = self.flows[key]
            flow.last_time = ts

            is_fwd = self._is_forward(pkt, flow)

            if is_fwd:
                flow.fwd_packets += 1
                flow.fwd_bytes += pkt.get("packet_len", 0)
                flow.fwd_pkt_sizes.append(pkt.get("packet_len", 0))
                if flow.last_fwd_time > 0 and ts > flow.last_fwd_time:
                    flow.fwd_iats.append(ts - flow.last_fwd_time)
                flow.last_fwd_time = ts
            else:
                flow.bwd_packets += 1
                flow.bwd_bytes += pkt.get("packet_len", 0)
                flow.bwd_pkt_sizes.append(pkt.get("packet_len", 0))
                if flow.last_bwd_time > 0 and ts > flow.last_bwd_time:
                    flow.bwd_iats.append(ts - flow.last_bwd_time)
                flow.last_bwd_time = ts

            # TCP flags
            flags = pkt.get("tcp_flags")
            if flags:
                if flags.get("syn"):
                    flow.syn_count += 1
                if flags.get("ack"):
                    flow.ack_count += 1
                if flags.get("rst"):
                    flow.rst_count += 1
                if flags.get("fin"):
                    flow.fin_count += 1
                if flags.get("psh"):
                    flow.psh_count += 1

            # Update source IP tracking (for port scan detection)
            src_state = self.source_ips[pkt["src_ip"]]
            src_state.dst_ports.add(pkt["dst_port"])
            src_state.dst_ips.add(pkt["dst_ip"])
            src_state.flow_count += 1
            src_state.pkt_sizes.append(pkt.get("packet_len", 0))
            if flags and flags.get("syn"):
                src_state.syn_count += 1
            if flags and flags.get("rst"):
                src_state.rst_count += 1
            src_state.total_packets += 1

    def _process_dns(self, pkt: dict):
        """Collect DNS queries for DGA detection, filtering out local/mDNS noise.

        Only the QUERY direction (client -> resolver, dst_port 53) is scored. A
        DNS reply echoes the same question name back (src_port 53); counting both
        would emit two identical DGA alerts per domain. Scoring the query only
        keeps one alert per lookup.
        """
        dns_query = pkt.get("dns_query")
        if not dns_query or self._is_safe_domain(dns_query):
            return
        # Skip the reply direction (server answering from :53) to avoid
        # double-counting each domain.
        if pkt.get("src_port") == 53 and pkt.get("dst_port") != 53:
            return
        with self.lock:
            self.dns_queries.append({
                "domain": dns_query,
                "src_ip": pkt["src_ip"],
                "dst_ip": pkt["dst_ip"],
                "timestamp_us": pkt["timestamp_us"],
            })

    @staticmethod
    def _is_safe_domain(domain: str) -> bool:
        """Check if a domain should be excluded from DGA analysis.
        
        Filters out:
        - mDNS / .local domains
        - Service discovery records (_tcp, _udp, etc.)
        - Reverse DNS (.arpa)
        - Internal network suffixes
        - Known infrastructure domains (CDNs, cloud providers)
        """
        dl = domain.lower()

        # Local/internal suffixes
        safe_suffixes = (
            ".local", ".localhost", ".internal", ".lan", ".home",
            ".intranet", ".corp", ".arpa", ".test", ".invalid",
            ".example", ".localdomain",
        )
        for suffix in safe_suffixes:
            if dl.endswith(suffix):
                return True

        # Service discovery prefixes (RFC 6763)
        if dl.startswith("_") or "._tcp." in dl or "._udp." in dl:
            return True

        # Multicast DNS destinations
        dst_indicators = ("224.0.0.251", "ff02::fb")
        # (dst IP filtering is handled upstream, but this catches any leaks)

        # Known safe infrastructure domains that look "random" but are legit
        safe_patterns = (
            ".akamaiedge.net", ".akamai.net", ".akamaihd.net",
            ".cloudfront.net", ".amazonaws.com", ".azure.com",
            ".googleapis.com", ".gstatic.com", ".googleusercontent.com",
            ".googlevideo.com", ".google.com", ".microsoft.com",
            ".windows.net", ".windowsupdate.com", ".office365.com",
            ".office.com", ".live.com", ".msedge.net",
            ".fbcdn.net", ".facebook.com", ".instagram.com",
            ".apple.com", ".icloud.com", ".cdn-apple.com",
            ".digicert.com", ".verisign.com", ".letsencrypt.org",
            ".github.com", ".github.io", ".githubusercontent.com",
            ".stackoverflow.com", ".cloudflare.com", ".fastly.net",
            ".cdn77.org", ".edgecastcdn.net", ".cedexis.com",
            # AI/ML services
            ".openai.com", ".openrouter.ai", ".anthropic.com",
            ".huggingface.co", ".replicate.com", ".together.ai",
            # Common services that may look suspicious
            ".spotify.com", ".discord.com", ".discord.gg",
            ".twitch.tv", ".netflix.com", ".whatsapp.com",
            ".telegram.org", ".signal.org",
        )
        for pattern in safe_patterns:
            if dl.endswith(pattern):
                return True

        # Exact-match safe domains (no subdomain prefix)
        safe_exact = {
            "openrouter.ai", "openai.com", "anthropic.com", "together.ai",
            "huggingface.co", "replicate.com", "spotify.com", "discord.com",
            "netflix.com", "twitch.tv", "whatsapp.com", "telegram.org",
            "signal.org", "zoom.us", "slack.com", "notion.so",
        }
        # Extract the registrable domain (last two labels)
        labels = dl.split(".")
        if len(labels) >= 2:
            reg_domain = ".".join(labels[-2:])
            if reg_domain in safe_exact:
                return True

        return False

    def _compute_flow_features(self, flow: FlowState) -> inference_pb2.FlowFeatures:
        """Compute feature vector for a single flow."""
        duration = max(flow.last_time - flow.start_time, 0.001)
        total_packets = flow.fwd_packets + flow.bwd_packets
        total_bytes = flow.fwd_bytes + flow.bwd_bytes

        all_iats = flow.fwd_iats + flow.bwd_iats

        return inference_pb2.FlowFeatures(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            flow_duration=duration * 1_000_000,  # microseconds
            total_fwd_packets=flow.fwd_packets,
            total_bwd_packets=flow.bwd_packets,
            flow_bytes_per_sec=total_bytes / duration if duration > 0 else 0,
            flow_packets_per_sec=total_packets / duration if duration > 0 else 0,
            flow_iat_mean=np.mean(all_iats) * 1_000_000 if all_iats else 0,
            flow_iat_std=np.std(all_iats) * 1_000_000 if len(all_iats) > 1 else 0,
            flow_iat_max=max(all_iats) * 1_000_000 if all_iats else 0,
            flow_iat_min=min(all_iats) * 1_000_000 if all_iats else 0,
            fwd_iat_mean=np.mean(flow.fwd_iats) * 1_000_000 if flow.fwd_iats else 0,
            bwd_iat_mean=np.mean(flow.bwd_iats) * 1_000_000 if flow.bwd_iats else 0,
            fwd_packet_len_mean=np.mean(flow.fwd_pkt_sizes) if flow.fwd_pkt_sizes else 0,
            bwd_packet_len_mean=np.mean(flow.bwd_pkt_sizes) if flow.bwd_pkt_sizes else 0,
            packet_len_variance=np.var(flow.fwd_pkt_sizes + flow.bwd_pkt_sizes) if (flow.fwd_pkt_sizes + flow.bwd_pkt_sizes) else 0,
            avg_packet_size=total_bytes / total_packets if total_packets > 0 else 0,
            syn_flag_count=flow.syn_count,
            ack_flag_count=flow.ack_count,
            rst_flag_count=flow.rst_count,
            fin_flag_count=flow.fin_count,
            psh_flag_count=flow.psh_count,
            down_up_ratio=flow.bwd_bytes / max(flow.fwd_bytes, 1),
            fwd_bytes=flow.fwd_bytes,
            bwd_bytes=flow.bwd_bytes,
        )

    def _compute_portscan_features(self, src_ip: str, state: SourceIPState) -> inference_pb2.FlowFeatures:
        """Compute port scan features for a source IP."""
        ports = list(state.dst_ports)
        port_entropy = 0.0
        if len(ports) > 1:
            freq = Counter(ports)
            total = sum(freq.values())
            probs = [c / total for c in freq.values()]
            port_entropy = -sum(p * math.log2(p) for p in probs if p > 0)

        syn_ratio = state.syn_count / max(state.total_packets, 1)
        rst_ratio = state.rst_count / max(state.total_packets, 1)

        return inference_pb2.FlowFeatures(
            src_ip=src_ip,
            unique_dst_ports=len(state.dst_ports),
            unique_dst_ips=len(state.dst_ips),
            total_flows_in_window=state.flow_count,
            flow_duration=np.mean(state.flow_durations) if state.flow_durations else 0,
            syn_ratio=syn_ratio,
            port_entropy=port_entropy,
            packet_len_variance=np.std(state.pkt_sizes) if state.pkt_sizes else 0,
            rst_flag_count=rst_ratio,
            flow_packets_per_sec=state.total_packets / WINDOW_SECONDS,
            total_fwd_packets=state.total_packets,
            total_bwd_packets=0,
        )

    def _run_inference(self):
        """Run inference on accumulated data and produce alerts."""
        with self.lock:
            flows = dict(self.flows)
            source_ips = dict(self.source_ips)
            dns_queries = list(self.dns_queries)
            # Reset state for next window
            self.flows = {}
            self.source_ips = defaultdict(SourceIPState)
            self.dns_queries = []

        alerts_produced = 0

        # --- DDoS Detection (per flow) ---
        if flows:
            flow_features = []
            flow_keys = []
            for key, flow in flows.items():
                if flow.fwd_packets + flow.bwd_packets >= 3:  # Min packets threshold
                    # Skip multicast/broadcast destinations — not attacks
                    if (flow.dst_ip.startswith("224.") or flow.dst_ip.startswith("239.")
                            or flow.dst_ip == "255.255.255.255"
                            or flow.dst_ip.startswith("ff02:")):
                        continue
                    features = self._compute_flow_features(flow)
                    flow_features.append(features)
                    flow_keys.append(key)

            if flow_features:
                try:
                    batch_req = inference_pb2.FlowBatchRequest(
                        features=flow_features,
                        detection_type="ddos",
                    )
                    batch_resp = self.grpc_stub.PredictFlowBatch(batch_req, timeout=5.0)

                    for i, pred in enumerate(batch_resp.predictions):
                        if pred.threat_class != "BENIGN" and pred.confidence >= CONFIDENCE_THRESHOLD:
                            flow = flows[flow_keys[i]]
                            alert = self._create_alert(
                                threat_class=pred.threat_class,
                                confidence=pred.confidence,
                                severity=pred.severity,
                                src_ip=flow.src_ip,
                                dst_ip=flow.dst_ip,
                                src_port=flow.src_port,
                                dst_port=flow.dst_port,
                                evidence={
                                    "flow_bytes_per_sec": flow.fwd_bytes / max(flow.last_time - flow.start_time, 0.001),
                                    "syn_count": flow.syn_count,
                                    "fwd_packets": flow.fwd_packets,
                                    "bwd_packets": flow.bwd_packets,
                                    "duration_ms": (flow.last_time - flow.start_time) * 1000,
                                },
                            )
                            self._produce_alert(alert)
                            alerts_produced += 1
                except grpc.RpcError as e:
                    logger.error(f"gRPC error (DDoS): {e.code()} {e.details()}")

        # --- PortScan Detection ---
        # Handled in real-time by _process_portscan_packet() using the local
        # portscan model + StreamingWindower. No batch gRPC call needed.

        # --- DGA Detection (per DNS query) ---
        if dns_queries:
            dns_features = []
            for query in dns_queries:
                domain = query["domain"]
                feat = self._compute_dns_features(domain)
                dns_features.append(feat)

            if dns_features:
                try:
                    batch_req = inference_pb2.DnsBatchRequest(features=dns_features)
                    batch_resp = self.grpc_stub.PredictDnsBatch(batch_req, timeout=5.0)

                    for i, pred in enumerate(batch_resp.predictions):
                        if pred.threat_class != "BENIGN" and pred.confidence >= CONFIDENCE_THRESHOLD:
                            query = dns_queries[i]
                            alert = self._create_alert(
                                threat_class=pred.threat_class,
                                confidence=pred.confidence,
                                severity=pred.severity,
                                src_ip=query["src_ip"],
                                dst_ip=query["dst_ip"],
                                src_port=0,
                                dst_port=53,
                                evidence={
                                    "domain": query["domain"],
                                    "entropy": self._domain_entropy(query["domain"]),
                                    "length": len(query["domain"]),
                                },
                            )
                            self._produce_alert(alert)
                            alerts_produced += 1
                except grpc.RpcError as e:
                    logger.error(f"gRPC error (DGA): {e.code()} {e.details()}")

        if alerts_produced > 0:
            logger.info(f"Window complete: {len(flows)} flows, {len(dns_queries)} DNS queries, {alerts_produced} alerts")

    def _compute_dns_features(self, domain: str) -> inference_pb2.DnsFeatures:
        """Compute DNS features for DGA detection."""
        parts = domain.lower().split(".")
        sld = parts[0] if parts else domain

        entropy = 0.0
        if len(sld) > 0:
            freq = Counter(sld)
            probs = [c / len(sld) for c in freq.values()]
            entropy = -sum(p * math.log2(p) for p in probs if p > 0)

        max_consonant_run = 0
        current = 0
        for c in sld:
            if c in "bcdfghjklmnpqrstvwxyz":
                current += 1
                max_consonant_run = max(max_consonant_run, current)
            else:
                current = 0

        return inference_pb2.DnsFeatures(
            domain=domain,
            length=len(sld),
            entropy=entropy,
            digit_ratio=sum(c.isdigit() for c in sld) / max(len(sld), 1),
            consonant_ratio=sum(c in "bcdfghjklmnpqrstvwxyz" for c in sld) / max(len(sld), 1),
            vowel_ratio=sum(c in "aeiou" for c in sld) / max(len(sld), 1),
            unique_char_ratio=len(set(sld)) / max(len(sld), 1),
            max_consonant_run=max_consonant_run,
            num_dots=domain.count("."),
        )

    def _domain_entropy(self, domain: str) -> float:
        """Quick entropy calculation for evidence."""
        sld = domain.lower().split(".")[0]
        if not sld:
            return 0.0
        freq = Counter(sld)
        probs = [c / len(sld) for c in freq.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def _create_alert(self, threat_class: str, confidence: float, severity: str,
                      src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      evidence: dict) -> dict:
        """Create standardized alert JSON."""
        return {
            "alert_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "threat_class": threat_class,
            "confidence": round(confidence, 4),
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "flow_id": f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
            "evidence": evidence,
            "model_version": "1.0.0",
        }

    def _produce_alert(self, alert: dict):
        """Produce alert to Kafka."""
        self.producer.produce(
            topic=KAFKA_OUTPUT_TOPIC,
            key=alert["src_ip"].encode("utf-8"),
            value=json.dumps(alert).encode("utf-8"),
        )
        self.producer.poll(0)

    def run(self):
        """Main event loop."""
        logger.info("Starting feature extraction loop...")

        # Wait for gRPC server to be ready
        self._wait_for_grpc()

        packets_in_window = 0

        try:
            while True:
                msg = self.consumer.poll(timeout=0.1)

                if msg is not None and not msg.error():
                    try:
                        pkt = json.loads(msg.value().decode("utf-8"))
                        self._update_flow(pkt)
                        self._process_dns(pkt)
                        self._process_portscan_packet(pkt)
                        packets_in_window += 1
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.warning(f"Invalid packet record: {e}")

                elif msg is not None and msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error(f"Kafka error: {msg.error()}")

                # Check if window has elapsed
                elapsed = time.time() - self.window_start
                if elapsed >= WINDOW_SECONDS:
                    if packets_in_window > 0:
                        logger.debug(f"Window closed: {packets_in_window} packets in {elapsed:.1f}s")
                        # Reset cross-detector suppression for this window.
                        # PortScan runs FIRST and claims scanner sources, then
                        # DDoS claims flood destinations; C2 then skips any
                        # claimed endpoint. window_claimed_srcs is cleared here
                        # so each window starts fresh.
                        self.window_claimed_dsts = set()
                        self.window_claimed_srcs = set()
                        # Flush any still-open SYN-only scan probes into the
                        # windower, then release windows that are complete under
                        # the lateness allowance as of NOW. Without this, a scan
                        # burst that ends cleanly (traffic then stops) leaves its
                        # final window held forever and PortScan never fires.
                        self._flush_open_scan_probes(time.time())
                        released = self.portscan_windower.tick(time.time())
                        self._score_portscan_windows(released)
                        self._score_ddos()
                        self._score_encrypted_malware()
                        self._score_exfiltration()
                        self._score_c2_beacon()
                        self._run_inference()
                    packets_in_window = 0
                    self.window_start = time.time()
                    self.producer.flush()

        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            self.consumer.close()
            self.producer.flush()
            self.grpc_channel.close()

    def _wait_for_grpc(self):
        """Wait for gRPC inference server to become available."""
        logger.info(f"Waiting for gRPC server at {GRPC_INFERENCE_HOST}...")
        for attempt in range(30):
            try:
                health_resp = self.grpc_stub.HealthCheck(
                    inference_pb2.Empty(), timeout=2.0
                )
                if health_resp.healthy:
                    logger.info(f"gRPC server ready. Models: {health_resp.loaded_models}")
                    return
            except grpc.RpcError:
                pass
            time.sleep(2)
        logger.warning("gRPC server not responding after 60s, proceeding anyway...")


if __name__ == "__main__":
    extractor = FeatureExtractor()
    extractor.run()
