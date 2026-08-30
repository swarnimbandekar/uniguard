"""
DDoS Flow Detector.

Detects volumetric and protocol DDoS attacks from flow-level metadata:
SYN floods, UDP amplification, volumetric floods, HTTP floods.

Operates on FlowState objects at window boundaries — no payload decryption.
"""

import json
import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)


class DDoSDetector:
    """Scores flows for DDoS attack patterns."""

    def __init__(self, model_path: Path):
        self.model = None
        self.metadata = None
        self.threshold = 0.5
        self.model_name = "ddos_flow"
        self._load(model_path)

    def _load(self, model_path: Path):
        meta_path = model_path.with_suffix(".metadata.json")
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata not found: {meta_path}")

        with open(meta_path) as f:
            self.metadata = json.load(f)
        self.threshold = self.metadata["decision_threshold"]
        self.model_name = self.metadata.get("model_name", "ddos_flow")
        self.model = joblib.load(model_path)

        logger.info(f"Loaded DDoS model: {self.model_name}")
        logger.info(f"  Threshold: {self.threshold:.4f}, "
                    f"Throughput: {self.metadata['constraints']['throughput_flows_per_sec']} flows/sec")

    def extract_features(self, flow) -> Optional[np.ndarray]:
        """Extract 31-feature vector from a FlowState."""
        total_pkts = flow.fwd_packets + flow.bwd_packets
        if total_pkts < 5:
            return None

        duration = max(flow.last_time - flow.start_time, 0.001)
        total_bytes = flow.fwd_bytes + flow.bwd_bytes

        fwd_bpp = flow.fwd_bytes / max(flow.fwd_packets, 1)
        bwd_bpp = flow.bwd_bytes / max(flow.bwd_packets, 1)

        # Packet size stats (approximate from per-packet lists)
        all_sizes = flow.fwd_pkt_sizes + flow.bwd_pkt_sizes
        pkt_size_mean = float(np.mean(all_sizes)) if all_sizes else 0.0
        pkt_size_std = float(np.std(all_sizes)) if len(all_sizes) > 1 else 0.0
        pkt_size_max = max(all_sizes) if all_sizes else 0
        pkt_size_min = min(all_sizes) if all_sizes else 0

        # IATs
        fwd_iat_mean = float(np.mean(flow.fwd_iats)) if flow.fwd_iats else duration
        fwd_iat_std = float(np.std(flow.fwd_iats)) if len(flow.fwd_iats) > 1 else 0.0
        bwd_iat_mean = float(np.mean(flow.bwd_iats)) if flow.bwd_iats else duration
        bwd_iat_std = float(np.std(flow.bwd_iats)) if len(flow.bwd_iats) > 1 else 0.0

        # Flag ratios
        syn_ratio = flow.syn_count / max(total_pkts, 1)
        ack_ratio = flow.ack_count / max(total_pkts, 1)
        rst_ratio = flow.rst_count / max(total_pkts, 1)
        fin_ratio = flow.fin_count / max(total_pkts, 1)
        psh_ratio = flow.psh_count / max(total_pkts, 1)

        bytes_ratio = flow.fwd_bytes / max(total_bytes, 1)
        pkt_ratio = flow.fwd_packets / max(total_pkts, 1)
        down_up_ratio = flow.bwd_bytes / max(flow.fwd_bytes, 1)

        common_ports = {80, 443, 22, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389}
        is_common = 1 if flow.dst_port in common_ports else 0

        if duration < 0.1:
            dur_bucket = 0
        elif duration < 1.0:
            dur_bucket = 1
        elif duration < 10.0:
            dur_bucket = 2
        else:
            dur_bucket = 3

        features = [
            duration, total_bytes, total_pkts, flow.fwd_bytes, flow.bwd_bytes,
            flow.fwd_packets, flow.bwd_packets,
            total_bytes / duration,  # bytes_per_sec
            total_pkts / duration,   # pkts_per_sec
            fwd_bpp, bwd_bpp, pkt_size_mean, pkt_size_std,
            pkt_size_max, pkt_size_min,
            fwd_iat_mean, fwd_iat_std, bwd_iat_mean, bwd_iat_std,
            syn_ratio, ack_ratio, rst_ratio, fin_ratio, psh_ratio,
            flow.syn_count, bytes_ratio, pkt_ratio, down_up_ratio,
            flow.dst_port, is_common, dur_bucket,
        ]
        return np.array([features], dtype=np.float64)

    def score(self, flow) -> Optional[float]:
        x = self.extract_features(flow)
        if x is None:
            return None
        return float(self.model.predict_proba(x)[0][1])

    def is_attack(self, score: float) -> bool:
        return score >= self.threshold

    def severity(self, score: float) -> str:
        if score >= 0.99:
            return "CRITICAL"
        elif score >= 0.95:
            return "HIGH"
        elif score >= 0.90:
            return "MEDIUM"
        else:
            return "LOW"
