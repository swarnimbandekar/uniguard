"""C2 beaconing detector — production runner (SIH handoff).

Passive, read-only, streaming, metadata-only. Consumes a native Zeek conn.log incrementally
and emits standardized C2_BEACONING alerts as JSONL. Runs the fast (60s/10s) and/or deep
(300s/60s) detector as INDEPENDENT instances (no score fusion).

Usage:
    python run_detector.py --conn /path/to/conn.log --out alerts.jsonl
    python run_detector.py --conn conn.log --detector fast --internal-prefix 10.0.
    python run_detector.py --conn conn.log --detector both --max-flows 200000

The Zeek uid is carried as alert context only. Endpoint/host IPs are never model features.
"""
import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # use the bundled c2beacon package
from c2beacon.sources import read_zeek_conn_log, ensure_datetime  # noqa: E402
from c2beacon.streaming_ext import StreamingBeaconDetectorExt  # noqa: E402

EVIDENCE_FEATURES = ["endpoint_host_fanin", "n_flows", "dst_recurrence", "host_endpoint_fanout",
                     "iat_mean", "iat_cov", "mean_pkts", "iat_madn", "dur_mean", "dur_cov",
                     "pkts_cov", "bytes_mean", "host_flow_share"]
DETECTORS = {
    "fast": ("models/c2_detector_60s_10s_ext13.joblib", 60, 10, "c2_fast_60s", "c2_60s_10s"),
    "deep": ("models/c2_detector_300s_60s_ext13.joblib", 300, 60, "c2_deep_300s", "c2_300s_60s"),
}


def alert_record(a):
    ev = a.evidence
    return {"timestamp": a.timestamp, "window_start": a.window_start,
            "detector_id": ev.get("detector_id"), "timescale": ev.get("timescale"),
            "flow_id": a.flow_id, "threat_class": a.threat_class,
            "confidence": round(float(a.confidence), 6),
            "evidence": {"unit": {"orig_h": ev.get("orig_h"), "resp_h": ev.get("resp_h"),
                                  "resp_p": ev.get("resp_p"), "proto": ev.get("proto")},
                         "n_contributing_flows": ev.get("n_contributing_flows"),
                         "features": {f: ev.get(f) for f in EVIDENCE_FEATURES}}}


def load_conn(path, max_flows):
    raw = read_zeek_conn_log(path)
    ts = ensure_datetime(raw["ts"])
    keep = ts.notna().to_numpy()
    idx = np.flatnonzero(keep)
    idx = idx[np.argsort(ts.to_numpy()[idx], kind="stable")]
    if max_flows and len(idx) > max_flows:
        idx = idx[:max_flows]
    g = lambda c, d="-": raw.get(c, pd.Series(d, index=raw.index))  # noqa: E731
    df = pd.DataFrame({
        "ts": ts.to_numpy()[idx],
        "orig_h": raw["id.orig_h"].astype(str).to_numpy()[idx],
        "resp_h": raw["id.resp_h"].astype(str).to_numpy()[idx],
        "resp_p": pd.to_numeric(raw["id.resp_p"], errors="coerce").to_numpy()[idx],
        "proto": raw["proto"].astype(str).str.lower().str.strip().to_numpy()[idx],
        "orig_pkts": pd.to_numeric(g("orig_pkts"), errors="coerce").fillna(0).to_numpy()[idx],
        "resp_pkts": pd.to_numeric(g("resp_pkts"), errors="coerce").fillna(0).to_numpy()[idx],
        "duration": pd.to_numeric(g("duration"), errors="coerce").fillna(0.0).to_numpy()[idx],
        "orig_ip_bytes": pd.to_numeric(g("orig_ip_bytes"), errors="coerce").fillna(0.0).to_numpy()[idx],
        "resp_ip_bytes": pd.to_numeric(g("resp_ip_bytes"), errors="coerce").fillna(0.0).to_numpy()[idx],
        "uid": raw["uid"].astype(str).to_numpy()[idx] if "uid" in raw.columns else None,
    })
    return df


def make_detector(key, origin, internal_prefixes):
    art, L, S, timescale, did = DETECTORS[key]
    bundle = joblib.load(os.path.join(HERE, art))
    det = StreamingBeaconDetectorExt(model=bundle["pipeline"], threshold=bundle["threshold"],
                                     origin=origin, window_s=L, stride_s=S,
                                     internal_prefixes=internal_prefixes, feature_only=False)
    det.detector_id = did
    det.timescale = timescale
    return det


def main():
    ap = argparse.ArgumentParser(description="Passive C2-beaconing detector (Zeek conn.log -> JSONL alerts)")
    ap.add_argument("--conn", required=True, help="path to native Zeek conn.log")
    ap.add_argument("--out", default="alerts.jsonl", help="output JSONL path")
    ap.add_argument("--detector", choices=["fast", "deep", "both"], default="both")
    ap.add_argument("--internal-prefix", default="147.32.",
                    help="internal originator prefix (comma-separated); 'none' to score all")
    ap.add_argument("--max-flows", type=int, default=0, help="cap flows (0 = all)")
    args = ap.parse_args()

    pref = None if args.internal_prefix.lower() == "none" else tuple(args.internal_prefix.split(","))
    df = load_conn(args.conn, args.max_flows)
    if len(df) == 0:
        print("no parseable flows", flush=True); return
    origin = pd.Timestamp(df["ts"].min()).floor("1s")
    keys = ["fast", "deep"] if args.detector == "both" else [args.detector]
    dets = {k: make_detector(k, origin, pref) for k in keys}
    print(f"flows={len(df):,} origin={origin} detectors={keys} internal_prefix={pref}", flush=True)

    n_alerts = 0
    with open(args.out, "w") as f:
        for r in df.itertuples(index=False):
            for det in dets.values():
                for a in det.push(ts=r.ts, orig_h=r.orig_h, resp_h=r.resp_h, resp_p=r.resp_p,
                                  proto=r.proto, orig_pkts=r.orig_pkts, resp_pkts=r.resp_pkts,
                                  duration=r.duration, orig_ip_bytes=r.orig_ip_bytes,
                                  resp_ip_bytes=r.resp_ip_bytes, uid=r.uid):
                    f.write(json.dumps(alert_record(a)) + "\n"); n_alerts += 1
        for det in dets.values():
            for a in det.flush():
                f.write(json.dumps(alert_record(a)) + "\n"); n_alerts += 1
    print(f"wrote {n_alerts} alerts -> {args.out}", flush=True)


if __name__ == "__main__":
    main()
