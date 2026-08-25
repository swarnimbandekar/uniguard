"""
Test the retrained DGA model by injecting DNS queries into Kafka.
Tests both false positive resistance (real domains) and true detection (DGA domains).

Usage:
    python scripts/test_dga.py
    python scripts/test_dga.py --attack-only
    python scripts/test_dga.py --benign-only
"""

import json
import sys
import time
import uuid
import argparse
import random
import math
from pathlib import Path
from collections import Counter
from datetime import datetime

import numpy as np
import joblib

# Load model directly for local testing (no gRPC needed)
ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "ml-service" / "models"

sys.path.insert(0, str(ROOT / "ml-service"))

try:
    from confluent_kafka import Producer
except ImportError:
    print("ERROR: pip install confluent-kafka")
    sys.exit(1)


def extract_dga_features(domain: str) -> dict:
    """Same feature extraction as the retrained model."""
    parts = domain.lower().split(".")
    sld = parts[0] if parts else domain
    full_no_tld = ".".join(parts[:-1]) if len(parts) > 1 else domain
    features = {}
    features["sld_length"] = len(sld)
    features["full_length"] = len(domain)
    features["num_dots"] = domain.count(".")
    features["num_labels"] = len(parts)
    features["max_label_length"] = max(len(p) for p in parts) if parts else 0
    features["digit_ratio"] = sum(c.isdigit() for c in sld) / max(len(sld), 1)
    features["alpha_ratio"] = sum(c.isalpha() for c in sld) / max(len(sld), 1)
    features["consonant_ratio"] = sum(c in "bcdfghjklmnpqrstvwxyz" for c in sld) / max(len(sld), 1)
    features["vowel_ratio"] = sum(c in "aeiou" for c in sld) / max(len(sld), 1)
    features["hyphen_ratio"] = sld.count("-") / max(len(sld), 1)
    if len(sld) > 0:
        freq = Counter(sld)
        probs = [count / len(sld) for count in freq.values()]
        features["entropy"] = -sum(p * math.log2(p) for p in probs)
    else:
        features["entropy"] = 0
    if len(full_no_tld) > 0:
        freq2 = Counter(full_no_tld.replace(".", ""))
        probs2 = [c / sum(freq2.values()) for c in freq2.values()]
        features["full_entropy"] = -sum(p * math.log2(p) for p in probs2)
    else:
        features["full_entropy"] = 0
    max_c = 0
    cur = 0
    for c in sld:
        if c in "bcdfghjklmnpqrstvwxyz":
            cur += 1
            max_c = max(max_c, cur)
        else:
            cur = 0
    features["max_consonant_run"] = max_c
    features["unique_char_ratio"] = len(set(sld)) / max(len(sld), 1)
    common_bigrams = {
        "th", "he", "in", "en", "nt", "re", "er", "an", "ti", "es",
        "on", "at", "se", "nd", "or", "ar", "al", "te", "co", "de",
        "to", "ra", "et", "ed", "it", "sa", "em", "ro", "st", "le",
        "ou", "ng", "ne", "io", "ec", "is", "la", "ea", "ic", "el",
        "oo", "ll", "ma", "go", "ch", "sh", "li", "ve", "ge", "ck",
    }
    if len(sld) >= 2:
        bigrams = [sld[i:i+2] for i in range(len(sld)-1)]
        features["common_bigram_ratio"] = sum(1 for bg in bigrams if bg in common_bigrams) / len(bigrams)
    else:
        features["common_bigram_ratio"] = 0
    transitions = 0
    for i in range(len(sld) - 1):
        if sld[i].isdigit() != sld[i+1].isdigit():
            transitions += 1
    features["digit_alpha_transitions"] = transitions / max(len(sld) - 1, 1)
    features["starts_with_digit"] = float(sld[0].isdigit()) if sld else 0
    features["ends_with_digit"] = float(sld[-1].isdigit()) if sld else 0
    popular_tlds = {".com", ".net", ".org", ".edu", ".gov", ".co", ".io", ".dev"}
    tld = "." + parts[-1] if parts else ""
    features["popular_tld"] = float(tld in popular_tlds)
    return features


def predict_domain(model, vectorizer, domain):
    """Predict if a domain is DGA."""
    feat = extract_dga_features(domain)
    stat_array = np.array([list(feat.values())])
    sld = domain.lower().split(".")[0]
    ngram_array = vectorizer.transform([sld]).toarray()
    x = np.hstack([stat_array, ngram_array])
    pred = model.predict(x)[0]
    conf = float(model.predict_proba(x)[0].max())
    return ("DGA" if pred == 1 else "LEGIT"), conf


def main():
    parser = argparse.ArgumentParser(description="Test DGA model + push alerts to Kafka")
    parser.add_argument("--attack-only", action="store_true", help="Only inject DGA domains")
    parser.add_argument("--benign-only", action="store_true", help="Only test benign (no Kafka)")
    parser.add_argument("--kafka-broker", default="localhost:9092")
    args = parser.parse_args()

    # Load model
    print("Loading DGA model...")
    model = joblib.load(MODELS / "dga_gb.pkl")
    vectorizer = joblib.load(MODELS / "dga_vectorizer.pkl")
    print("Model loaded.\n")

    # === Benign test (false positive check) ===
    if not args.attack_only:
        print("=" * 60)
        print("  FALSE POSITIVE TEST — these should all be LEGIT")
        print("=" * 60)
        benign = [
            "google.com", "facebook.com", "cdn77.org", "fastly.net",
            "clients4.google.com", "s3.amazonaws.com", "e11290.dscg.akamaiedge.net",
            "a1b2c3d4e5f6.cloudfront.net", "connectivity-check.ubuntu.com",
            "fbcdn-sphotos-a-a.akamaihd.net", "lh3.googleusercontent.com",
            "tile-service.weather.microsoft.com", "ocsp.digicert.com",
            "safebrowsing.googleapis.com", "update.googleapis.com",
            "detectportal.firefox.com", "px8v2k3m.cdn.example.com",
            "teams.microsoft.com", "outlook.office365.com",
            "api.github.com", "registry.npmjs.org",
        ]
        fp = 0
        for d in benign:
            label, conf = predict_domain(model, vectorizer, d)
            flag = " <<<< FALSE POSITIVE!" if label == "DGA" else ""
            if label == "DGA":
                fp += 1
            print(f"  {label:5s} ({conf:.3f}) {d}{flag}")
        print(f"\n  Result: {fp}/{len(benign)} false positives ({100*fp/len(benign):.0f}%)")
        if fp == 0:
            print("  PASSED — zero false positives on real-world domains")
        print()

    if args.benign_only:
        return

    # === DGA attack test (true positive check + push to Kafka) ===
    print("=" * 60)
    print("  DGA ATTACK TEST — these should all trigger alerts")
    print("=" * 60)

    # Generate DGA-like domains
    rng = random.Random(int(time.time()))
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    dga_tlds = [".com", ".net", ".org", ".info", ".biz", ".xyz", ".top", ".tk"]

    dga_domains = []
    for _ in range(20):
        length = rng.randint(12, 24)
        name = "".join(rng.choices(list(chars), k=length))
        tld = rng.choice(dga_tlds)
        dga_domains.append(name + tld)

    # Test predictions
    detected = 0
    for d in dga_domains:
        label, conf = predict_domain(model, vectorizer, d)
        flag = " <<<< MISSED!" if label == "LEGIT" else ""
        if label == "DGA":
            detected += 1
        print(f"  {label:5s} ({conf:.3f}) {d}{flag}")

    print(f"\n  Result: {detected}/{len(dga_domains)} detected ({100*detected/len(dga_domains):.0f}%)")
    if detected == len(dga_domains):
        print("  PASSED — all DGA domains detected")
    print()

    # Push to Kafka
    print("=" * 60)
    print("  PUSHING DGA ALERTS TO KAFKA → DASHBOARD")
    print("=" * 60)

    producer = Producer({"bootstrap.servers": args.kafka_broker, "linger.ms": "5"})
    pushed = 0

    for d in dga_domains:
        label, conf = predict_domain(model, vectorizer, d)
        if label == "DGA" and conf >= 0.8:
            alert = {
                "alert_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "threat_class": "DGA",
                "confidence": conf,
                "severity": "CRITICAL" if conf >= 0.95 else "HIGH" if conf >= 0.9 else "MEDIUM",
                "src_ip": "192.168.1.50",
                "dst_ip": "8.8.8.8",
                "src_port": rng.randint(1024, 65535),
                "dst_port": 53,
                "flow_id": f"192.168.1.50:{rng.randint(1024,65535)}-8.8.8.8:53",
                "evidence": {
                    "domain": d,
                    "entropy": extract_dga_features(d)["entropy"],
                    "sld_length": extract_dga_features(d)["sld_length"],
                    "common_bigram_ratio": extract_dga_features(d)["common_bigram_ratio"],
                    "digit_ratio": extract_dga_features(d)["digit_ratio"],
                },
                "model_version": "dga-v2-retrained",
            }
            producer.produce("threat-alerts", key=b"192.168.1.50", value=json.dumps(alert).encode())
            pushed += 1

    producer.flush(5)
    print(f"\n  Pushed {pushed} DGA alerts to Kafka")
    print(f"  Dashboard: http://localhost:3000")

    # Check results
    try:
        import requests
        time.sleep(2)
        r = requests.get("http://localhost:8001/api/stats", timeout=5)
        if r.ok:
            stats = r.json()
            print(f"\n  Dashboard stats:")
            print(f"    Total alerts: {stats['total_alerts']}")
            print(f"    By class: {stats['by_threat_class']}")
            print(f"    By severity: {stats['by_severity']}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
