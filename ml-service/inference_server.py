"""
gRPC Inference Server for Threat Detection.
Loads pre-trained models and serves predictions for DDoS, PortScan, and DGA.
"""

import os
import math
import logging
from collections import Counter
from concurrent import futures
from pathlib import Path

import grpc
import joblib
import numpy as np

import inference_pb2
import inference_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MODEL_VERSION = "1.0.0"
MODELS_DIR = Path(os.environ.get("MODELS_DIR", "/app/models"))


def compute_severity(confidence: float) -> str:
    """Map confidence score to severity level."""
    if confidence >= 0.95:
        return "CRITICAL"
    elif confidence >= 0.90:
        return "HIGH"
    elif confidence >= 0.80:
        return "MEDIUM"
    else:
        return "LOW"


def extract_dga_features_from_domain(domain: str) -> dict:
    """Extract character-level features from a domain (improved v2)."""
    parts = domain.lower().split(".")
    sld = parts[0] if parts else domain
    full_no_tld = ".".join(parts[:-1]) if len(parts) > 1 else domain

    features = {}

    # Length features
    features["sld_length"] = len(sld)
    features["full_length"] = len(domain)
    features["num_dots"] = domain.count(".")
    features["num_labels"] = len(parts)
    features["max_label_length"] = max(len(p) for p in parts) if parts else 0

    # Character distribution (on SLD only)
    features["digit_ratio"] = sum(c.isdigit() for c in sld) / max(len(sld), 1)
    features["alpha_ratio"] = sum(c.isalpha() for c in sld) / max(len(sld), 1)
    features["consonant_ratio"] = sum(c in "bcdfghjklmnpqrstvwxyz" for c in sld) / max(len(sld), 1)
    features["vowel_ratio"] = sum(c in "aeiou" for c in sld) / max(len(sld), 1)
    features["hyphen_ratio"] = sld.count("-") / max(len(sld), 1)

    # Shannon entropy (on SLD)
    if len(sld) > 0:
        freq = Counter(sld)
        probs = [count / len(sld) for count in freq.values()]
        features["entropy"] = -sum(p * math.log2(p) for p in probs)
    else:
        features["entropy"] = 0

    # Entropy on full domain
    if len(full_no_tld) > 0:
        freq2 = Counter(full_no_tld.replace(".", ""))
        probs2 = [c / sum(freq2.values()) for c in freq2.values()]
        features["full_entropy"] = -sum(p * math.log2(p) for p in probs2)
    else:
        features["full_entropy"] = 0

    # Consecutive consonants
    max_consonants = 0
    current = 0
    for c in sld:
        if c in "bcdfghjklmnpqrstvwxyz":
            current += 1
            max_consonants = max(max_consonants, current)
        else:
            current = 0
    features["max_consonant_run"] = max_consonants

    # Unique char ratio
    features["unique_char_ratio"] = len(set(sld)) / max(len(sld), 1)

    # Bigram pronounceability
    common_bigrams = {
        "th", "he", "in", "en", "nt", "re", "er", "an", "ti", "es",
        "on", "at", "se", "nd", "or", "ar", "al", "te", "co", "de",
        "to", "ra", "et", "ed", "it", "sa", "em", "ro", "st", "le",
        "ou", "ng", "ne", "io", "ec", "is", "la", "ea", "ic", "el",
        "oo", "ll", "ma", "go", "ch", "sh", "li", "ve", "ge", "ck",
    }
    if len(sld) >= 2:
        bigrams = [sld[i:i+2] for i in range(len(sld)-1)]
        common_count = sum(1 for bg in bigrams if bg in common_bigrams)
        features["common_bigram_ratio"] = common_count / len(bigrams)
    else:
        features["common_bigram_ratio"] = 0

    # Digit-alpha transitions
    transitions = 0
    for i in range(len(sld) - 1):
        if sld[i].isdigit() != sld[i+1].isdigit():
            transitions += 1
    features["digit_alpha_transitions"] = transitions / max(len(sld) - 1, 1)

    # Starts/ends with digit
    features["starts_with_digit"] = float(sld[0].isdigit()) if sld else 0
    features["ends_with_digit"] = float(sld[-1].isdigit()) if sld else 0

    # Popular TLD indicator
    popular_tlds = {".com", ".net", ".org", ".edu", ".gov", ".co", ".io", ".dev"}
    tld = "." + parts[-1] if parts else ""
    features["popular_tld"] = float(tld in popular_tlds)

    return features


class ThreatDetectorServicer(inference_pb2_grpc.ThreatDetectorServicer):
    def __init__(self):
        self.models = {}
        self._load_models()

    def _load_models(self):
        """Load all pre-trained models."""
        logger.info(f"Loading models from {MODELS_DIR}")

        # DDoS model — STANDBY (will be retrained later)
        logger.info("DDoS detection: STANDBY (model pending retraining)")

        # PortScan model (now handled by external portscan-10s2s via live_portscan.py)
        # The friend's calibrated model runs outside Docker and pushes alerts directly to Kafka
        logger.info("PortScan detection: handled by external portscan-10s2s model (Zeek-based)")

        # DGA model
        dga_path = MODELS_DIR / "dga_gb.pkl"
        if dga_path.exists():
            self.models["dga"] = {
                "model": joblib.load(dga_path),
                "vectorizer": joblib.load(MODELS_DIR / "dga_vectorizer.pkl"),
                "features": joblib.load(MODELS_DIR / "dga_features.pkl"),
            }
            logger.info("Loaded DGA model (Gradient Boosting)")
        else:
            logger.warning(f"DGA model not found at {dga_path}")

        logger.info(f"Total models loaded: {len(self.models)}")

    def _predict_ddos(self, features) -> tuple:
        """DDoS detection — STANDBY. Model will be retrained later."""
        return "BENIGN", 0.0

    def _predict_portscan(self, features) -> tuple:
        """Run PortScan prediction on fan-out features."""
        if "portscan" not in self.models:
            return "UNKNOWN", 0.0

        model = self.models["portscan"]["model"]
        scaler = self.models["portscan"]["scaler"]
        feature_names = self.models["portscan"]["features"]

        feature_map = {
            "unique_dst_ports": features.unique_dst_ports,
            "unique_dst_ips": features.unique_dst_ips,
            "total_flows": features.total_flows_in_window,
            "avg_duration": features.flow_duration,
            "syn_ratio": features.syn_ratio,
            "port_entropy": features.port_entropy,
            "pkt_size_std": features.packet_len_variance,
            "rst_ratio": features.rst_flag_count / max(features.total_fwd_packets + features.total_bwd_packets, 1),
            "flow_rate": features.flow_packets_per_sec,
        }

        x = np.array([[feature_map.get(f, 0.0) for f in feature_names]])
        x_scaled = scaler.transform(x)
        pred = model.predict(x_scaled)[0]
        confidence = float(model.predict_proba(x_scaled)[0].max())

        label = "PortScan" if pred == 1 else "BENIGN"
        return label, confidence

    def _predict_dga(self, dns_features) -> tuple:
        """Run DGA prediction on domain features."""
        if "dga" not in self.models:
            return "UNKNOWN", 0.0

        model = self.models["dga"]["model"]
        vectorizer = self.models["dga"]["vectorizer"]

        domain = dns_features.domain

        # Statistical features
        stat_feat = extract_dga_features_from_domain(domain)
        stat_array = np.array([list(stat_feat.values())])

        # N-gram features (on SLD only, matching training)
        sld = domain.lower().split(".")[0]
        ngram_array = vectorizer.transform([sld]).toarray()

        # Combine
        x = np.hstack([stat_array, ngram_array])
        pred = model.predict(x)[0]
        confidence = float(model.predict_proba(x)[0].max())

        label = "DGA" if pred == 1 else "BENIGN"
        return label, confidence

    def PredictFlow(self, request, context):
        """Handle single flow prediction."""
        detection_type = request.detection_type.lower()

        if detection_type == "ddos":
            label, confidence = self._predict_ddos(request.features)
        elif detection_type == "portscan":
            label, confidence = self._predict_portscan(request.features)
        else:
            # Try both and return the one with higher attack confidence
            ddos_label, ddos_conf = self._predict_ddos(request.features)
            scan_label, scan_conf = self._predict_portscan(request.features)

            if ddos_label != "BENIGN" and ddos_conf > scan_conf:
                label, confidence = ddos_label, ddos_conf
            elif scan_label != "BENIGN":
                label, confidence = scan_label, scan_conf
            else:
                label = "BENIGN"
                confidence = max(ddos_conf, scan_conf)

        return inference_pb2.PredictResponse(
            threat_class=label,
            confidence=confidence,
            severity=compute_severity(confidence) if label != "BENIGN" else "LOW",
            model_version=MODEL_VERSION,
        )

    def PredictFlowBatch(self, request, context):
        """Handle batch flow prediction."""
        responses = []
        for features in request.features:
            single_req = inference_pb2.FlowPredictRequest(
                features=features,
                detection_type=request.detection_type,
            )
            resp = self.PredictFlow(single_req, context)
            responses.append(resp)

        return inference_pb2.BatchResponse(predictions=responses)

    def PredictDns(self, request, context):
        """Handle single DNS/DGA prediction."""
        label, confidence = self._predict_dga(request.features)

        return inference_pb2.PredictResponse(
            threat_class=label,
            confidence=confidence,
            severity=compute_severity(confidence) if label != "BENIGN" else "LOW",
            model_version=MODEL_VERSION,
        )

    def PredictDnsBatch(self, request, context):
        """Handle batch DNS/DGA prediction."""
        responses = []
        for features in request.features:
            single_req = inference_pb2.DnsPredictRequest(features=features)
            resp = self.PredictDns(single_req, context)
            responses.append(resp)

        return inference_pb2.BatchResponse(predictions=responses)

    def HealthCheck(self, request, context):
        """Health check endpoint."""
        return inference_pb2.HealthResponse(
            healthy=True,
            version=MODEL_VERSION,
            loaded_models=list(self.models.keys()),
        )


def serve():
    """Start gRPC server."""
    port = os.environ.get("GRPC_PORT", "50051")

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=[
            ("grpc.max_send_message_length", 50 * 1024 * 1024),
            ("grpc.max_receive_message_length", 50 * 1024 * 1024),
        ],
    )
    inference_pb2_grpc.add_ThreatDetectorServicer_to_server(
        ThreatDetectorServicer(), server
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logger.info(f"Inference server started on port {port}")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
