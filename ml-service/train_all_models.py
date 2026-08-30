"""
Train all remaining ML models for the threat detection pipeline.

Models trained here:
  1. DDoS Detector — flow-level volumetric/protocol flood detection
  2. Data Exfiltration Detector — asymmetric outbound anomaly detection

Already existing (NOT retrained here):
  - DGA: models/dga_gb.pkl (trained by retrain_dga.py)
  - Encrypted Malware: models/encrypted_malware_flow.joblib (trained by train_encrypted_malware.py)
  - PortScan: models/portscan-10s2s.joblib (calibrated model)
  - C2 Beaconing: ml-service/c2beacon/ (rule-based periodicity, no model artifact)

All models follow the constraints:
  a. Read-only ingest (passive, no return path)
  b. No payload decryption (metadata only)
  c. Streaming-compatible (score at window boundaries)
  d. Defined throughput target (benchmarked)
  e. Standardized alert schema
"""

import json
import logging
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, f1_score, roc_auc_score, confusion_matrix,
    precision_recall_curve
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)


# =============================================================================
# MODEL 1: DDoS DETECTOR
# =============================================================================
# Features: flow-level rate stats, packet sizes, flag ratios, source entropy
# Detects: SYN floods, UDP amplification, volumetric floods

DDOS_FEATURE_COLS = [
    "duration",
    "total_bytes",
    "total_packets",
    "fwd_bytes",
    "bwd_bytes",
    "fwd_packets",
    "bwd_packets",
    "bytes_per_sec",
    "pkts_per_sec",
    "fwd_bytes_per_pkt",
    "bwd_bytes_per_pkt",
    "pkt_size_mean",
    "pkt_size_std",
    "pkt_size_max",
    "pkt_size_min",
    "fwd_iat_mean",
    "fwd_iat_std",
    "bwd_iat_mean",
    "bwd_iat_std",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "psh_ratio",
    "syn_count",
    "bytes_ratio",            # fwd / total — DDoS often one-sided
    "pkt_ratio",
    "down_up_ratio",
    "dst_port",
    "is_common_port",         # port 80/443/53 etc
    "flow_duration_bucket",   # 0=micro(<0.1s), 1=short(<1s), 2=medium(<10s), 3=long
]


def generate_ddos_data(rng, n_benign=20000, n_attack=10000):
    """Generate synthetic DDoS training data."""
    benign = []
    attacks = []

    # --- Benign flows ---
    for _ in range(n_benign):
        profile = rng.choice(["web", "streaming", "dns", "api", "ssh"])

        if profile == "web":
            duration = rng.uniform(0.5, 60.0)
            fwd_bytes = rng.uniform(500, 10000)
            bwd_bytes = rng.uniform(5000, 2000000)
            fwd_pkts = rng.randint(5, 50)
            bwd_pkts = rng.randint(10, 1000)
            dst_port = rng.choice([80, 443, 443, 443, 8080])
            syn_r = rng.uniform(0.01, 0.08)
            ack_r = rng.uniform(0.6, 0.9)
            rst_r = rng.uniform(0.0, 0.02)

        elif profile == "streaming":
            duration = rng.uniform(30.0, 600.0)
            fwd_bytes = rng.uniform(2000, 20000)
            bwd_bytes = rng.uniform(1000000, 100000000)
            fwd_pkts = rng.randint(50, 500)
            bwd_pkts = rng.randint(1000, 60000)
            dst_port = rng.choice([443, 443, 8443])
            syn_r = rng.uniform(0.001, 0.02)
            ack_r = rng.uniform(0.8, 0.95)
            rst_r = rng.uniform(0.0, 0.01)

        elif profile == "dns":
            duration = rng.uniform(0.01, 2.0)
            fwd_bytes = rng.uniform(50, 500)
            bwd_bytes = rng.uniform(100, 2000)
            fwd_pkts = rng.randint(1, 5)
            bwd_pkts = rng.randint(1, 5)
            dst_port = 53
            syn_r = 0.0
            ack_r = 0.0
            rst_r = 0.0

        elif profile == "api":
            duration = rng.uniform(0.05, 5.0)
            fwd_bytes = rng.uniform(200, 5000)
            bwd_bytes = rng.uniform(500, 50000)
            fwd_pkts = rng.randint(2, 20)
            bwd_pkts = rng.randint(2, 30)
            dst_port = rng.choice([443, 8080, 3000, 5000])
            syn_r = rng.uniform(0.02, 0.1)
            ack_r = rng.uniform(0.7, 0.9)
            rst_r = rng.uniform(0.0, 0.02)

        else:  # ssh
            duration = rng.uniform(5.0, 3600.0)
            fwd_bytes = rng.uniform(5000, 500000)
            bwd_bytes = rng.uniform(5000, 500000)
            fwd_pkts = rng.randint(50, 5000)
            bwd_pkts = rng.randint(50, 5000)
            dst_port = 22
            syn_r = rng.uniform(0.001, 0.01)
            ack_r = rng.uniform(0.8, 0.95)
            rst_r = rng.uniform(0.0, 0.01)

        benign.append(_ddos_features(
            duration, fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts,
            dst_port, syn_r, ack_r, rst_r, rng, is_attack=False
        ))

    # --- DDoS attacks ---
    for _ in range(n_attack):
        attack_type = rng.choice(["syn_flood", "syn_flood", "udp_amp", "volumetric", "http_flood"])

        if attack_type == "syn_flood":
            # Massive SYN packets, tiny size, short or no response
            duration = rng.uniform(0.1, 10.0)
            fwd_bytes = rng.uniform(50000, 5000000)
            bwd_bytes = rng.uniform(0, 5000)  # Almost no response
            fwd_pkts = rng.randint(1000, 100000)
            bwd_pkts = rng.randint(0, 50)
            dst_port = rng.choice([80, 443, 22, 25, 3389])
            syn_r = rng.uniform(0.7, 1.0)  # Almost all SYNs
            ack_r = rng.uniform(0.0, 0.1)
            rst_r = rng.uniform(0.0, 0.3)

        elif attack_type == "udp_amp":
            # UDP amplification: small request, massive response
            duration = rng.uniform(1.0, 30.0)
            fwd_bytes = rng.uniform(100, 5000)
            bwd_bytes = rng.uniform(1000000, 500000000)  # Amplified
            fwd_pkts = rng.randint(10, 500)
            bwd_pkts = rng.randint(5000, 500000)
            dst_port = rng.choice([53, 123, 161, 1900, 11211])
            syn_r = 0.0
            ack_r = 0.0
            rst_r = 0.0

        elif attack_type == "volumetric":
            # High-volume traffic flood
            duration = rng.uniform(1.0, 60.0)
            fwd_bytes = rng.uniform(10000000, 1000000000)
            bwd_bytes = rng.uniform(0, 100000)
            fwd_pkts = rng.randint(10000, 1000000)
            bwd_pkts = rng.randint(0, 1000)
            dst_port = rng.choice([80, 443, 53, 22])
            syn_r = rng.uniform(0.1, 0.5)
            ack_r = rng.uniform(0.2, 0.6)
            rst_r = rng.uniform(0.0, 0.2)

        else:  # http_flood
            # Many complete HTTP connections, high rate
            duration = rng.uniform(1.0, 30.0)
            fwd_bytes = rng.uniform(500000, 50000000)
            bwd_bytes = rng.uniform(1000000, 100000000)
            fwd_pkts = rng.randint(5000, 500000)
            bwd_pkts = rng.randint(5000, 500000)
            dst_port = rng.choice([80, 443])
            syn_r = rng.uniform(0.05, 0.2)
            ack_r = rng.uniform(0.5, 0.8)
            rst_r = rng.uniform(0.01, 0.1)

        attacks.append(_ddos_features(
            duration, fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts,
            dst_port, syn_r, ack_r, rst_r, rng, is_attack=True
        ))

    return benign, attacks


def _ddos_features(duration, fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts,
                   dst_port, syn_r, ack_r, rst_r, rng, is_attack):
    total_bytes = fwd_bytes + bwd_bytes
    total_pkts = fwd_pkts + bwd_pkts
    bytes_per_sec = total_bytes / max(duration, 0.001)
    pkts_per_sec = total_pkts / max(duration, 0.001)
    fwd_bpp = fwd_bytes / max(fwd_pkts, 1)
    bwd_bpp = bwd_bytes / max(bwd_pkts, 1)

    all_sizes = ([fwd_bpp] * max(fwd_pkts, 1)) + ([bwd_bpp] * max(bwd_pkts, 1))
    pkt_size_mean = np.mean(all_sizes[:100])  # Approximate
    pkt_size_std = np.std(all_sizes[:100]) if len(all_sizes) > 1 else 0
    pkt_size_max = max(fwd_bpp, bwd_bpp)
    pkt_size_min = min(fwd_bpp, bwd_bpp) if bwd_pkts > 0 else fwd_bpp

    # IATs
    if is_attack:
        fwd_iat_mean = duration / max(fwd_pkts, 1) * rng.uniform(0.8, 1.2)
        fwd_iat_std = fwd_iat_mean * rng.uniform(0.01, 0.2)
    else:
        fwd_iat_mean = duration / max(fwd_pkts, 1) * rng.uniform(0.5, 1.5)
        fwd_iat_std = fwd_iat_mean * rng.uniform(0.3, 2.0)

    bwd_iat_mean = duration / max(bwd_pkts, 1)
    bwd_iat_std = bwd_iat_mean * rng.uniform(0.1, 1.0)

    fin_r = rng.uniform(0.0, 0.05)
    psh_r = rng.uniform(0.1, 0.4) if not is_attack else rng.uniform(0.0, 0.1)
    syn_count = int(syn_r * total_pkts)
    bytes_ratio = fwd_bytes / max(total_bytes, 1)
    pkt_ratio = fwd_pkts / max(total_pkts, 1)
    down_up_ratio = bwd_bytes / max(fwd_bytes, 1)

    common_ports = {80, 443, 22, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389}
    is_common = 1 if dst_port in common_ports else 0

    if duration < 0.1:
        dur_bucket = 0
    elif duration < 1.0:
        dur_bucket = 1
    elif duration < 10.0:
        dur_bucket = 2
    else:
        dur_bucket = 3

    return [
        duration, total_bytes, total_pkts, fwd_bytes, bwd_bytes,
        fwd_pkts, bwd_pkts, bytes_per_sec, pkts_per_sec,
        fwd_bpp, bwd_bpp, pkt_size_mean, pkt_size_std,
        pkt_size_max, pkt_size_min, fwd_iat_mean, fwd_iat_std,
        bwd_iat_mean, bwd_iat_std, syn_r, ack_r, rst_r,
        fin_r, psh_r, syn_count, bytes_ratio, pkt_ratio,
        down_up_ratio, dst_port, is_common, dur_bucket,
    ]


# =============================================================================
# MODEL 2: DATA EXFILTRATION DETECTOR
# =============================================================================
# Features: outbound volume anomalies, byte ratios, timing patterns
# Detects: Bulk data theft via encrypted channels

EXFIL_FEATURE_COLS = [
    "duration",
    "fwd_bytes",
    "bwd_bytes",
    "fwd_packets",
    "bwd_packets",
    "total_bytes",
    "bytes_ratio_out",         # fwd / total — high = upload-heavy
    "pkt_ratio_out",
    "fwd_bytes_per_pkt",
    "bwd_bytes_per_pkt",
    "fwd_pkt_size_std",
    "bwd_pkt_size_std",
    "bytes_per_sec",
    "pkts_per_sec",
    "fwd_iat_mean",
    "fwd_iat_std",
    "bwd_iat_mean",
    "bwd_iat_std",
    "iat_regularity",
    "up_down_ratio",           # fwd_bytes / bwd_bytes — key exfil signal
    "dst_port",
    "is_std_https",
    "is_high_port",
    "syn_ratio",
    "ack_ratio",
    "psh_ratio",
    "fin_ratio",
    "fwd_burst_rate",          # fwd_pkts / duration — upload intensity
    "response_ratio",          # bwd_pkts / fwd_pkts — server barely responds
]


def generate_exfil_data(rng, n_benign=20000, n_exfil=10000):
    """Generate training data for exfiltration detection."""
    benign = []
    exfil = []

    # --- Benign flows (including legitimate uploads) ---
    for _ in range(n_benign):
        profile = rng.choice([
            "browsing", "cloud_upload", "email_send", "video_call",
            "api", "download", "streaming"
        ])

        if profile == "browsing":
            duration = rng.uniform(0.5, 30.0)
            fwd_bytes = rng.uniform(500, 8000)
            bwd_bytes = rng.uniform(10000, 1000000)
            fwd_pkts = rng.randint(5, 40)
            bwd_pkts = rng.randint(20, 500)
            dst_port = 443

        elif profile == "cloud_upload":
            # Legitimate cloud uploads (Drive, OneDrive, S3)
            duration = rng.uniform(5.0, 300.0)
            fwd_bytes = rng.uniform(100000, 50000000)
            bwd_bytes = rng.uniform(50000, 500000)  # ACKs + progress responses
            fwd_pkts = rng.randint(100, 30000)
            bwd_pkts = rng.randint(50, 5000)
            dst_port = 443

        elif profile == "email_send":
            duration = rng.uniform(1.0, 10.0)
            fwd_bytes = rng.uniform(5000, 500000)
            bwd_bytes = rng.uniform(1000, 10000)
            fwd_pkts = rng.randint(10, 200)
            bwd_pkts = rng.randint(5, 50)
            dst_port = rng.choice([443, 587, 465])

        elif profile == "video_call":
            duration = rng.uniform(60.0, 3600.0)
            fwd_bytes = rng.uniform(5000000, 500000000)
            bwd_bytes = rng.uniform(5000000, 500000000)
            fwd_pkts = rng.randint(5000, 500000)
            bwd_pkts = rng.randint(5000, 500000)
            dst_port = rng.choice([443, 3478, 3479])

        elif profile == "api":
            duration = rng.uniform(0.05, 3.0)
            fwd_bytes = rng.uniform(200, 5000)
            bwd_bytes = rng.uniform(500, 50000)
            fwd_pkts = rng.randint(2, 15)
            bwd_pkts = rng.randint(2, 30)
            dst_port = 443

        elif profile == "download":
            duration = rng.uniform(2.0, 120.0)
            fwd_bytes = rng.uniform(500, 5000)
            bwd_bytes = rng.uniform(1000000, 100000000)
            fwd_pkts = rng.randint(10, 100)
            bwd_pkts = rng.randint(500, 50000)
            dst_port = 443

        else:  # streaming
            duration = rng.uniform(30.0, 600.0)
            fwd_bytes = rng.uniform(2000, 20000)
            bwd_bytes = rng.uniform(5000000, 500000000)
            fwd_pkts = rng.randint(50, 500)
            bwd_pkts = rng.randint(5000, 300000)
            dst_port = 443

        benign.append(_exfil_features(
            duration, fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts,
            dst_port, rng, is_exfil=False
        ))

    # --- Exfiltration flows ---
    for _ in range(n_exfil):
        exfil_type = rng.choice([
            "bulk_steal", "bulk_steal",  # Most common
            "slow_drip", "burst_exfil", "dns_tunnel_like"
        ])

        if exfil_type == "bulk_steal":
            # Large upload, minimal server response (just ACKs)
            duration = rng.uniform(5.0, 120.0)
            fwd_bytes = rng.uniform(500000, 100000000)
            bwd_bytes = rng.uniform(500, 10000)  # Almost nothing back
            fwd_pkts = rng.randint(300, 50000)
            bwd_pkts = rng.randint(3, 30)
            dst_port = rng.choice([443, 443, 8443, 4443, 9999, 8080])

        elif exfil_type == "slow_drip":
            # Slow exfil over long period, small but steady upload
            duration = rng.uniform(300.0, 7200.0)
            fwd_bytes = rng.uniform(50000, 5000000)
            bwd_bytes = rng.uniform(500, 5000)
            fwd_pkts = rng.randint(50, 3000)
            bwd_pkts = rng.randint(5, 50)
            dst_port = rng.choice([443, 443, 8443])

        elif exfil_type == "burst_exfil":
            # Short intense burst
            duration = rng.uniform(0.5, 10.0)
            fwd_bytes = rng.uniform(1000000, 50000000)
            bwd_bytes = rng.uniform(200, 5000)
            fwd_pkts = rng.randint(500, 30000)
            bwd_pkts = rng.randint(2, 20)
            dst_port = rng.choice([443, 4443, 8443, 9999])

        else:  # dns_tunnel_like (over TCP/HTTPS)
            # Many small uploads, each with tiny response
            duration = rng.uniform(60.0, 1800.0)
            fwd_bytes = rng.uniform(100000, 2000000)
            bwd_bytes = rng.uniform(10000, 50000)
            fwd_pkts = rng.randint(500, 10000)
            bwd_pkts = rng.randint(100, 2000)
            dst_port = rng.choice([443, 443, 8443])

        exfil.append(_exfil_features(
            duration, fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts,
            dst_port, rng, is_exfil=True
        ))

    return benign, exfil


def _exfil_features(duration, fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts,
                    dst_port, rng, is_exfil):
    total_bytes = fwd_bytes + bwd_bytes
    total_pkts = fwd_pkts + bwd_pkts
    bytes_ratio_out = fwd_bytes / max(total_bytes, 1)
    pkt_ratio_out = fwd_pkts / max(total_pkts, 1)
    fwd_bpp = fwd_bytes / max(fwd_pkts, 1)
    bwd_bpp = bwd_bytes / max(bwd_pkts, 1)

    if is_exfil:
        fwd_pkt_std = fwd_bpp * rng.uniform(0.0, 0.2)  # Uniform uploads
        bwd_pkt_std = bwd_bpp * rng.uniform(0.0, 0.3)
    else:
        fwd_pkt_std = fwd_bpp * rng.uniform(0.2, 0.8)
        bwd_pkt_std = bwd_bpp * rng.uniform(0.2, 0.8)

    bytes_per_sec = total_bytes / max(duration, 0.001)
    pkts_per_sec = total_pkts / max(duration, 0.001)

    fwd_iat_mean = duration / max(fwd_pkts - 1, 1)
    bwd_iat_mean = duration / max(bwd_pkts - 1, 1)
    if is_exfil:
        fwd_iat_std = fwd_iat_mean * rng.uniform(0.01, 0.2)
        bwd_iat_std = bwd_iat_mean * rng.uniform(0.1, 0.5)
    else:
        fwd_iat_std = fwd_iat_mean * rng.uniform(0.3, 2.0)
        bwd_iat_std = bwd_iat_mean * rng.uniform(0.3, 2.0)

    avg_iat_mean = (fwd_iat_mean + bwd_iat_mean) / 2
    avg_iat_std = (fwd_iat_std + bwd_iat_std) / 2
    iat_regularity = 1.0 - min(avg_iat_std / max(avg_iat_mean, 0.001), 1.0)

    up_down_ratio = fwd_bytes / max(bwd_bytes, 1)
    is_std_https = 1 if dst_port == 443 else 0
    is_high_port = 1 if (dst_port > 1024 and dst_port not in (443, 8443, 8080)) else 0

    syn_ratio = rng.uniform(0.01, 0.08)
    ack_ratio = rng.uniform(0.7, 0.95)
    psh_ratio = rng.uniform(0.2, 0.6) if is_exfil else rng.uniform(0.1, 0.4)
    fin_ratio = rng.uniform(0.01, 0.05)

    fwd_burst_rate = fwd_pkts / max(duration, 0.001)
    response_ratio = bwd_pkts / max(fwd_pkts, 1)

    return [
        duration, fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts, total_bytes,
        bytes_ratio_out, pkt_ratio_out, fwd_bpp, bwd_bpp,
        fwd_pkt_std, bwd_pkt_std, bytes_per_sec, pkts_per_sec,
        fwd_iat_mean, fwd_iat_std, bwd_iat_mean, bwd_iat_std,
        iat_regularity, up_down_ratio, dst_port, is_std_https,
        is_high_port, syn_ratio, ack_ratio, psh_ratio, fin_ratio,
        fwd_burst_rate, response_ratio,
    ]


# =============================================================================
# TRAINING LOGIC
# =============================================================================

def train_model(name, feature_cols, benign_data, attack_data, model_file, meta_file):
    """Train a single model and save artifacts."""
    logger.info(f"\n{'='*60}")
    logger.info(f"TRAINING: {name}")
    logger.info(f"{'='*60}")

    X = np.array(benign_data + attack_data, dtype=np.float64)
    y = np.array([0] * len(benign_data) + [1] * len(attack_data))

    # Shuffle
    rng = np.random.RandomState(42)
    idx = rng.permutation(len(X))
    X, y = X[idx], y[idx]

    logger.info(f"  Samples: {len(X)} ({len(benign_data)} benign + {len(attack_data)} attack)")
    logger.info(f"  Features: {X.shape[1]}")
    assert X.shape[1] == len(feature_cols), f"Feature mismatch: {X.shape[1]} vs {len(feature_cols)}"

    # Train
    model = HistGradientBoostingClassifier(
        max_iter=200,
        max_depth=5,
        learning_rate=0.05,
        min_samples_leaf=20,
        random_state=42,
    )

    # 3-fold CV
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    cv_proba = cross_val_predict(model, X, y, cv=cv, method="predict_proba")[:, 1]
    cv_pred = (cv_proba >= 0.5).astype(int)

    auc = roc_auc_score(y, cv_proba)
    f1 = f1_score(y, cv_pred)
    acc = accuracy_score(y, cv_pred)
    tn, fp, fn, tp = confusion_matrix(y, cv_pred).ravel()
    fpr = fp / (fp + tn)
    recall = tp / (tp + fn)
    precision = tp / (tp + fp)

    # Optimal threshold
    precisions, recalls, thresholds = precision_recall_curve(y, cv_proba)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
    best_idx = np.argmax(f1_scores)
    threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5

    logger.info(f"  ROC-AUC:   {auc:.4f}")
    logger.info(f"  F1:        {f1:.4f}")
    logger.info(f"  Accuracy:  {acc:.4f}")
    logger.info(f"  Recall:    {recall:.4f}")
    logger.info(f"  Precision: {precision:.4f}")
    logger.info(f"  FPR:       {fpr:.4f}")
    logger.info(f"  Threshold: {threshold:.4f}")
    logger.info(f"  TP={tp} FP={fp} FN={fn} TN={tn}")

    # Retrain on full data
    model.fit(X, y)

    # Throughput test
    batch = X[:1000]
    start = time.perf_counter()
    for _ in range(50):
        model.predict_proba(batch)
    elapsed = time.perf_counter() - start
    throughput = int((1000 * 50) / elapsed)
    logger.info(f"  Throughput: {throughput} flows/sec")

    # Save
    joblib.dump(model, model_file)
    metadata = {
        "threat": name.lower().replace(" ", "_"),
        "model_name": model_file.stem,
        "model_file": model_file.name,
        "model_type": "HistGradientBoostingClassifier",
        "feature_cols": feature_cols,
        "n_features": len(feature_cols),
        "decision_threshold": threshold,
        "response_mode": "INTELLIGENCE_ONLY (passive, read-only)",
        "constraints": {
            "read_only_ingest": True,
            "no_payload_decryption": True,
            "streaming_compatible": True,
            "throughput_flows_per_sec": throughput,
            "standardized_alerts": True,
        },
        "metrics": {
            "roc_auc": auc, "f1": f1, "accuracy": acc,
            "recall": recall, "precision": precision, "fpr": fpr,
            "threshold": threshold,
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        },
    }
    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"  Saved: {model_file.name} + {meta_file.name}")
    return model


def main():
    logger.info("=" * 60)
    logger.info("TRAINING ALL THREAT DETECTION MODELS")
    logger.info("=" * 60)

    rng = np.random.RandomState(42)

    # --- 1. DDoS ---
    benign, attacks = generate_ddos_data(rng)
    train_model(
        "DDoS",
        DDOS_FEATURE_COLS,
        benign, attacks,
        MODELS_DIR / "ddos_flow.joblib",
        MODELS_DIR / "ddos_flow.metadata.json",
    )

    # --- 2. Data Exfiltration ---
    benign, exfil = generate_exfil_data(rng)
    train_model(
        "Data Exfiltration",
        EXFIL_FEATURE_COLS,
        benign, exfil,
        MODELS_DIR / "exfiltration_flow.joblib",
        MODELS_DIR / "exfiltration_flow.metadata.json",
    )

    logger.info("\n" + "=" * 60)
    logger.info("ALL MODELS TRAINED SUCCESSFULLY")
    logger.info("=" * 60)
    logger.info("\nModel inventory:")
    logger.info("  1. DDoS:              models/ddos_flow.joblib")
    logger.info("  2. Exfiltration:      models/exfiltration_flow.joblib")
    logger.info("  3. Encrypted Malware: models/encrypted_malware_flow.joblib (already exists)")
    logger.info("  4. DGA:               models/dga_gb.pkl (trained by retrain_dga.py)")
    logger.info("  5. PortScan:          models/portscan-10s2s.joblib (calibrated)")
    logger.info("  6. C2 Beaconing:      c2beacon/ (rule-based periodicity, no model file)")


if __name__ == "__main__":
    main()
