"""
Data Exfiltration Detector.

Detects bulk data theft over encrypted channels from flow metadata:
asymmetric upload volumes, low server response ratios, burst patterns.

Distinguishes from legitimate uploads (cloud sync, email, video calls)
by analyzing timing regularity, response patterns, and volume ratios.
"""

import json
import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)


class ExfiltrationDetector:
    """Scores flows for data exfiltration patterns."""

    def __init__(self, model_path: Path):
        self.model = None
        self.metadata = None
        self.threshold = 0.5
        self.model_name = "exfiltration_flow"
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
        self.model_name = self.metadata.get("model_name", "exfiltration_flow")
        self.model = joblib.load(model_path)

        logger.info(f"Loaded Exfiltration model: {self.model_name}")
        logger.info(f"  Threshold: {self.threshold:.4f}, "
                    f"Throughput: {self.metadata['constraints']['throughput_flows_per_sec']} flows/sec")

    def extract_features(self, flow) -> Optional[np.ndarray]:
        """Extract 29-feature vector from a FlowState."""
        total_pkts = flow.fwd_packets + flow.bwd_packets
        if total_pkts < 3:
            return None
        # Only TCP
        if flow.protocol != 6:
            return None
        # Need meaningful outbound data to be exfiltration
        if flow.fwd_bytes < 1000:
            return None

        duration = max(flow.last_time - flow.start_time, 0.001)
        total_bytes = flow.fwd_bytes + flow.bwd_bytes

        bytes_ratio_out = flow.fwd_bytes / max(total_bytes, 1)
        pkt_ratio_out = flow.fwd_packets / max(total_pkts, 1)
        fwd_bpp = flow.fwd_bytes / max(flow.fwd_packets, 1)
        bwd_bpp = flow.bwd_bytes / max(flow.bwd_packets, 1)

        fwd_pkt_std = float(np.std(flow.fwd_pkt_sizes)) if len(flow.fwd_pkt_sizes) > 1 else 0.0
        bwd_pkt_std = float(np.std(flow.bwd_pkt_sizes)) if len(flow.bwd_pkt_sizes) > 1 else 0.0

        bytes_per_sec = total_bytes / duration
        pkts_per_sec = total_pkts / duration

        fwd_iat_mean = float(np.mean(flow.fwd_iats)) if flow.fwd_iats else duration
        fwd_iat_std = float(np.std(flow.fwd_iats)) if len(flow.fwd_iats) > 1 else 0.0
        bwd_iat_mean = float(np.mean(flow.bwd_iats)) if flow.bwd_iats else duration
        bwd_iat_std = float(np.std(flow.bwd_iats)) if len(flow.bwd_iats) > 1 else 0.0

        avg_iat_mean = (fwd_iat_mean + bwd_iat_mean) / 2
        avg_iat_std = (fwd_iat_std + bwd_iat_std) / 2
        iat_regularity = 1.0 - min(avg_iat_std / max(avg_iat_mean, 0.001), 1.0)

        up_down_ratio = flow.fwd_bytes / max(flow.bwd_bytes, 1)
        is_std_https = 1 if flow.dst_port == 443 else 0
        is_high_port = 1 if (flow.dst_port > 1024 and flow.dst_port not in (443, 8443, 8080)) else 0

        syn_ratio = flow.syn_count / max(total_pkts, 1)
        ack_ratio = flow.ack_count / max(total_pkts, 1)
        psh_ratio = flow.psh_count / max(total_pkts, 1)
        fin_ratio = flow.fin_count / max(total_pkts, 1)

        fwd_burst_rate = flow.fwd_packets / duration
        response_ratio = flow.bwd_packets / max(flow.fwd_packets, 1)

        features = [
            duration, flow.fwd_bytes, flow.bwd_bytes,
            flow.fwd_packets, flow.bwd_packets, total_bytes,
            bytes_ratio_out, pkt_ratio_out, fwd_bpp, bwd_bpp,
            fwd_pkt_std, bwd_pkt_std, bytes_per_sec, pkts_per_sec,
            fwd_iat_mean, fwd_iat_std, bwd_iat_mean, bwd_iat_std,
            iat_regularity, up_down_ratio, flow.dst_port, is_std_https,
            is_high_port, syn_ratio, ack_ratio, psh_ratio, fin_ratio,
            fwd_burst_rate, response_ratio,
        ]
        return np.array([features], dtype=np.float64)

    def score(self, flow) -> Optional[float]:
        x = self.extract_features(flow)
        if x is None:
            return None

        ml_score = float(self.model.predict_proba(x)[0][1])

        # Rule-based override: unambiguous exfiltration signatures that the
        # synthetic-trained model may miss on real traffic.
        # Large outbound volume + heavily asymmetric (upload >> download).
        total_bytes = flow.fwd_bytes + flow.bwd_bytes
        up_down_ratio = flow.fwd_bytes / max(flow.bwd_bytes, 1)

        # Strong exfil signal: >500KB uploaded AND upload is 5x+ the download
        if flow.fwd_bytes > 500_000 and up_down_ratio > 5.0:
            return max(ml_score, 0.995)
        # Medium signal: >100KB uploaded AND upload is 10x+ the download
        if flow.fwd_bytes > 100_000 and up_down_ratio > 10.0:
            return max(ml_score, 0.992)

        return ml_score

    def is_exfiltration(self, score: float) -> bool:
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
