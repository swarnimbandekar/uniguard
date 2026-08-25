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

    def _load_portscan_model(self):
        """Load the portscan model and initialize the streaming windower."""
        try:
            if PORTSCAN_MODEL_PATH.exists():
                self.portscan_detector = PortScanDetector.load(
                    PORTSCAN_MODEL_PATH, allow_version_mismatch=True
                )
                self.portscan_windower = StreamingWindower(
                    spec=self.portscan_detector.window_spec,
                    lateness_seconds=5.0,
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
                or src_ip == "255.255.255.255"):
            return

        # For UDP: emit a flow immediately (stateless)
        if proto == 17:
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

        # TCP: track connection state to approximate conn_state
        # Use directional key (src -> dst:port)
        tcp_key = f"{src_ip}->{dst_ip}:{dst_port}"
        reverse_key = f"{dst_ip}->{src_ip}:{pkt['src_port']}"

        with self.lock:
            record = self._open_tcp_flows.get(tcp_key)

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
        for window in windows:
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
        """Collect DNS queries for DGA detection, filtering out local/mDNS noise."""
        dns_query = pkt.get("dns_query")
        if dns_query and not self._is_safe_domain(dns_query):
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
