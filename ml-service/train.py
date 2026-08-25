"""
Training script for cyber threat detection models.
Trains 3 models:
1. DDoS detector (Random Forest on flow features)
2. PortScan detector (Gradient Boosting on fan-out features)
3. DGA detector (Gradient Boosting on character + n-gram features)

Uses CIC-IDS2017 dataset (CSV format) for DDoS and PortScan.
Uses synthetic DGA domain lists for DGA detection.
"""

import os
import math
import json
import logging
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = Path("models")
DATA_DIR = Path("data")


# =============================================================================
# DDoS DETECTION MODEL
# =============================================================================

DDOS_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Packet Length Variance",
    "Average Packet Size",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "Down/Up Ratio",
    "Subflow Fwd Bytes",
    "Subflow Bwd Bytes",
]


def train_ddos_model(data_path: str = None):
    """Train Random Forest for DDoS detection."""
    logger.info("=== Training DDoS Detection Model ===")

    if data_path and os.path.exists(data_path):
        logger.info(f"Loading data from {data_path}")
        df = pd.read_csv(data_path)
        df.columns = df.columns.str.strip()
    else:
        logger.info("No dataset found. Generating synthetic training data...")
        df = _generate_synthetic_ddos_data()

    # Clean data
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Use available features
    available_features = [f for f in DDOS_FEATURES if f in df.columns]
    if not available_features:
        logger.warning("No matching features found. Using synthetic features.")
        df = _generate_synthetic_ddos_data()
        available_features = [f for f in DDOS_FEATURES if f in df.columns]

    logger.info(f"Using {len(available_features)} features: {available_features}")

    df.dropna(subset=available_features, inplace=True)

    X = df[available_features].values
    y = (df["Label"].str.strip() != "BENIGN").astype(int).values if "Label" in df.columns else df["label"].values

    logger.info(f"Dataset: {len(X)} samples, {y.sum()} attacks, {len(y) - y.sum()} benign")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=42
    )

    # Train Random Forest
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    f1 = f1_score(y_test, y_pred)
    logger.info(f"DDoS Model F1-Score: {f1:.4f}")
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["BENIGN", "DDoS"]))

    # Save model and metadata
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODELS_DIR / "ddos_rf.pkl")
    joblib.dump(available_features, MODELS_DIR / "ddos_features.pkl")

    metadata = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "features": available_features,
        "f1_score": float(f1),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
    }
    with open(MODELS_DIR / "ddos_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"DDoS model saved to {MODELS_DIR / 'ddos_rf.pkl'}")
    return clf


def _generate_synthetic_ddos_data(n_benign=5000, n_attack=5000):
    """Generate synthetic DDoS data for training when real data unavailable."""
    rng = np.random.default_rng(42)

    data = []

    # Benign traffic characteristics
    for _ in range(n_benign):
        data.append({
            "Flow Duration": rng.exponential(500000),
            "Total Fwd Packets": rng.integers(1, 50),
            "Total Backward Packets": rng.integers(1, 50),
            "Flow Bytes/s": rng.exponential(50000),
            "Flow Packets/s": rng.exponential(100),
            "Flow IAT Mean": rng.exponential(100000),
            "Flow IAT Std": rng.exponential(50000),
            "Flow IAT Max": rng.exponential(500000),
            "Flow IAT Min": rng.exponential(1000),
            "Fwd IAT Mean": rng.exponential(100000),
            "Bwd IAT Mean": rng.exponential(100000),
            "Fwd Packet Length Mean": rng.normal(500, 200),
            "Bwd Packet Length Mean": rng.normal(500, 200),
            "Packet Length Variance": rng.exponential(50000),
            "Average Packet Size": rng.normal(500, 200),
            "SYN Flag Count": rng.integers(0, 3),
            "ACK Flag Count": rng.integers(1, 50),
            "RST Flag Count": rng.integers(0, 2),
            "PSH Flag Count": rng.integers(0, 20),
            "Down/Up Ratio": rng.uniform(0.5, 2.0),
            "Subflow Fwd Bytes": rng.integers(100, 50000),
            "Subflow Bwd Bytes": rng.integers(100, 50000),
            "label": 0,
        })

    # DDoS attack characteristics (high rate, many SYNs, low variance)
    for _ in range(n_attack):
        data.append({
            "Flow Duration": rng.exponential(10000),
            "Total Fwd Packets": rng.integers(100, 10000),
            "Total Backward Packets": rng.integers(0, 5),
            "Flow Bytes/s": rng.exponential(5000000),
            "Flow Packets/s": rng.exponential(10000),
            "Flow IAT Mean": rng.exponential(100),
            "Flow IAT Std": rng.exponential(50),
            "Flow IAT Max": rng.exponential(1000),
            "Flow IAT Min": rng.exponential(10),
            "Fwd IAT Mean": rng.exponential(100),
            "Bwd IAT Mean": rng.exponential(500000),
            "Fwd Packet Length Mean": rng.normal(60, 10),
            "Bwd Packet Length Mean": rng.normal(0, 1),
            "Packet Length Variance": rng.exponential(100),
            "Average Packet Size": rng.normal(60, 10),
            "SYN Flag Count": rng.integers(50, 10000),
            "ACK Flag Count": rng.integers(0, 5),
            "RST Flag Count": rng.integers(0, 50),
            "PSH Flag Count": rng.integers(0, 2),
            "Down/Up Ratio": rng.uniform(0.0, 0.1),
            "Subflow Fwd Bytes": rng.integers(1000, 500000),
            "Subflow Bwd Bytes": rng.integers(0, 100),
            "label": 1,
        })

    return pd.DataFrame(data)


# =============================================================================
# PORT SCAN DETECTION MODEL
# =============================================================================

PORTSCAN_FEATURES = [
    "unique_dst_ports",
    "unique_dst_ips",
    "total_flows",
    "avg_duration",
    "syn_ratio",
    "port_entropy",
    "pkt_size_std",
    "rst_ratio",
    "flow_rate",
]


def train_portscan_model(data_path: str = None):
    """Train Gradient Boosting for PortScan detection."""
    logger.info("=== Training PortScan Detection Model ===")

    if data_path and os.path.exists(data_path):
        logger.info(f"Loading data from {data_path}")
        df = pd.read_csv(data_path)
    else:
        logger.info("Generating synthetic PortScan training data...")
        df = _generate_synthetic_portscan_data()

    feature_cols = [c for c in PORTSCAN_FEATURES if c in df.columns]
    logger.info(f"Using {len(feature_cols)} features")

    X = df[feature_cols].values
    y = df["label"].values

    logger.info(f"Dataset: {len(X)} samples, {y.sum()} scans, {len(y) - y.sum()} benign")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=42
    )

    # Standardize features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.1,
        random_state=42,
    )
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    f1 = f1_score(y_test, y_pred)
    logger.info(f"PortScan Model F1-Score: {f1:.4f}")
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["BENIGN", "PortScan"]))

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODELS_DIR / "portscan_gb.pkl")
    joblib.dump(scaler, MODELS_DIR / "portscan_scaler.pkl")
    joblib.dump(feature_cols, MODELS_DIR / "portscan_features.pkl")

    metadata = {
        "model_type": "GradientBoostingClassifier",
        "n_estimators": 200,
        "features": feature_cols,
        "f1_score": float(f1),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
    }
    with open(MODELS_DIR / "portscan_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"PortScan model saved to {MODELS_DIR / 'portscan_gb.pkl'}")
    return clf


def _generate_synthetic_portscan_data(n_benign=5000, n_scan=5000):
    """Generate synthetic port scan data."""
    rng = np.random.default_rng(42)

    data = []

    # Benign: few unique destinations, normal patterns
    for _ in range(n_benign):
        n_ports = rng.integers(1, 5)
        data.append({
            "unique_dst_ports": n_ports,
            "unique_dst_ips": rng.integers(1, 3),
            "total_flows": rng.integers(1, 20),
            "avg_duration": rng.exponential(300000),
            "syn_ratio": rng.uniform(0.01, 0.3),
            "port_entropy": rng.uniform(0, 1.5),
            "pkt_size_std": rng.exponential(200),
            "rst_ratio": rng.uniform(0.0, 0.1),
            "flow_rate": rng.exponential(2),
            "label": 0,
        })

    # Port scan: many unique ports, high SYN ratio, uniform packet sizes
    for _ in range(n_scan):
        n_ports = rng.integers(50, 1000)
        data.append({
            "unique_dst_ports": n_ports,
            "unique_dst_ips": rng.integers(1, 10),
            "total_flows": rng.integers(50, 5000),
            "avg_duration": rng.exponential(1000),
            "syn_ratio": rng.uniform(0.7, 1.0),
            "port_entropy": rng.uniform(4.0, 10.0),
            "pkt_size_std": rng.exponential(10),
            "rst_ratio": rng.uniform(0.3, 0.9),
            "flow_rate": rng.exponential(100),
            "label": 1,
        })

    return pd.DataFrame(data)


# =============================================================================
# DGA DETECTION MODEL
# =============================================================================


def extract_dga_features(domain: str) -> dict:
    """Extract character-level features from a domain name."""
    parts = domain.lower().split(".")
    sld = parts[0] if parts else domain

    features = {}
    features["length"] = len(sld)
    features["full_length"] = len(domain)
    features["num_dots"] = domain.count(".")

    # Character distribution
    features["digit_ratio"] = sum(c.isdigit() for c in sld) / max(len(sld), 1)
    features["alpha_ratio"] = sum(c.isalpha() for c in sld) / max(len(sld), 1)
    features["consonant_ratio"] = (
        sum(c in "bcdfghjklmnpqrstvwxyz" for c in sld.lower()) / max(len(sld), 1)
    )
    features["vowel_ratio"] = sum(c in "aeiou" for c in sld.lower()) / max(len(sld), 1)

    # Shannon entropy
    if len(sld) > 0:
        freq = Counter(sld)
        probs = [count / len(sld) for count in freq.values()]
        features["entropy"] = -sum(p * math.log2(p) for p in probs)
    else:
        features["entropy"] = 0

    # Consecutive consonants
    max_consonants = 0
    current = 0
    for c in sld.lower():
        if c in "bcdfghjklmnpqrstvwxyz":
            current += 1
            max_consonants = max(max_consonants, current)
        else:
            current = 0
    features["max_consonant_run"] = max_consonants

    # Unique character ratio
    features["unique_char_ratio"] = len(set(sld)) / max(len(sld), 1)

    return features


def train_dga_model(legit_domains_path: str = None, dga_domains_path: str = None):
    """Train Gradient Boosting + n-gram for DGA detection."""
    logger.info("=== Training DGA Detection Model ===")

    if legit_domains_path and os.path.exists(legit_domains_path):
        with open(legit_domains_path) as f:
            legit_domains = [line.strip().split(",")[-1] if "," in line else line.strip() for line in f if line.strip()][:10000]
    else:
        logger.info("Using built-in legitimate domain samples...")
        legit_domains = _generate_legit_domains()

    if dga_domains_path and os.path.exists(dga_domains_path):
        with open(dga_domains_path) as f:
            dga_domains = [line.strip() for line in f if line.strip()][:10000]
    else:
        logger.info("Using synthetic DGA domains...")
        dga_domains = _generate_dga_domains()

    logger.info(f"Legit domains: {len(legit_domains)}, DGA domains: {len(dga_domains)}")

    # Build dataset
    all_domains = legit_domains + dga_domains
    labels = [0] * len(legit_domains) + [1] * len(dga_domains)

    # Extract statistical features
    stat_features = []
    for domain in all_domains:
        feat = extract_dga_features(domain)
        stat_features.append(list(feat.values()))

    stat_feature_names = list(extract_dga_features("example.com").keys())
    stat_array = np.array(stat_features)

    # N-gram features
    char_vectorizer = CountVectorizer(
        analyzer="char",
        ngram_range=(2, 4),
        max_features=300,
        lowercase=True,
    )
    ngram_features = char_vectorizer.fit_transform(all_domains)

    # Combine features
    X = hstack([csr_matrix(stat_array), ngram_features])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=42
    )

    clf = GradientBoostingClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
    )
    clf.fit(X_train.toarray(), y_train)

    y_pred = clf.predict(X_test.toarray())
    f1 = f1_score(y_test, y_pred)
    logger.info(f"DGA Model F1-Score: {f1:.4f}")
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["LEGIT", "DGA"]))

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODELS_DIR / "dga_gb.pkl")
    joblib.dump(char_vectorizer, MODELS_DIR / "dga_vectorizer.pkl")
    joblib.dump(stat_feature_names, MODELS_DIR / "dga_features.pkl")

    metadata = {
        "model_type": "GradientBoostingClassifier",
        "n_estimators": 300,
        "stat_features": stat_feature_names,
        "ngram_max_features": 300,
        "f1_score": float(f1),
        "train_samples": X_train.shape[0],
        "test_samples": X_test.shape[0],
    }
    with open(MODELS_DIR / "dga_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"DGA model saved to {MODELS_DIR / 'dga_gb.pkl'}")
    return clf


def _generate_legit_domains(n=5000):
    """Generate realistic-looking legitimate domains."""
    rng = np.random.default_rng(42)
    # Common English words used in domain names
    words = [
        "google", "facebook", "amazon", "microsoft", "apple", "netflix", "twitter",
        "linkedin", "github", "stackoverflow", "wikipedia", "reddit", "youtube",
        "instagram", "whatsapp", "telegram", "discord", "spotify", "adobe", "oracle",
        "cloud", "server", "mail", "shop", "store", "blog", "news", "tech", "dev",
        "app", "web", "net", "data", "info", "help", "support", "home", "page",
        "site", "online", "digital", "smart", "fast", "secure", "safe", "best",
        "top", "pro", "plus", "prime", "elite", "core", "hub", "lab", "base",
        "world", "global", "local", "city", "market", "trade", "finance", "health",
        "learn", "teach", "study", "code", "build", "design", "create", "make",
    ]
    tlds = [".com", ".net", ".org", ".io", ".dev", ".co", ".info", ".biz"]

    domains = []
    for _ in range(n):
        n_words = rng.integers(1, 3)
        name = "".join(rng.choice(words, size=n_words))
        tld = rng.choice(tlds)
        domains.append(name + tld)

    return domains


def _generate_dga_domains(n=5000):
    """Generate DGA-like domains (random characters)."""
    rng = np.random.default_rng(123)
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    tlds = [".com", ".net", ".org", ".info", ".biz", ".xyz", ".top", ".tk"]

    domains = []
    for _ in range(n):
        length = rng.integers(8, 25)
        name = "".join(rng.choice(list(chars), size=length))
        tld = rng.choice(tlds)
        domains.append(name + tld)

    return domains


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    logger.info("Starting model training pipeline")
    logger.info(f"Models will be saved to: {MODELS_DIR.absolute()}")

    # Check for CIC-IDS2017 data
    ddos_csv = DATA_DIR / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    portscan_csv = DATA_DIR / "Thursday-WorkingHours-Afternoon-PortScan.csv"
    legit_csv = DATA_DIR / "top-1m.csv"
    dga_csv = DATA_DIR / "dga_domains.txt"

    # Train all models
    train_ddos_model(str(ddos_csv) if ddos_csv.exists() else None)
    train_portscan_model(str(portscan_csv) if portscan_csv.exists() else None)
    train_dga_model(
        str(legit_csv) if legit_csv.exists() else None,
        str(dga_csv) if dga_csv.exists() else None,
    )

    logger.info("All models trained successfully!")
    logger.info(f"Model files in {MODELS_DIR.absolute()}:")
    for f in sorted(MODELS_DIR.iterdir()):
        size = f.stat().st_size / 1024
        logger.info(f"  {f.name}: {size:.1f} KB")
