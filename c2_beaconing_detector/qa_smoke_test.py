"""C2 beaconing detector — handoff SMOKE TEST (run from the handoff/ directory).

Self-contained: synthesizes a tiny native-format Zeek conn.log containing an unambiguous
coordinated beacon (many internal hosts contacting one endpoint at a fixed cadence) plus
benign noise, then drives the COMPLETE production path for both timescales and asserts:

  model loads            | feature schema matches | Zeek input parses | 60s detector runs
  300s detector runs     | alerts generated       | alert schema valid | bounded state

Streaming/batch parity and the throughput benchmark are verified by the repository scripts
referenced in C2_BEACONING_HANDOFF.md (they need the full CTU capture); this smoke test
confirms the shipped artifacts + package + schema load and run correctly on any conn.log.

Exit code 0 iff every check PASS. Writes nothing permanent (uses a temp conn.log).
"""
import json
import os
import sys
import tempfile

import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run_detector import load_conn, make_detector, alert_record, DETECTORS, EVIDENCE_FEATURES  # noqa: E402

SCHEMA = os.path.join(HERE, "schema", "alert_schema.json")
REQUIRED = ("timestamp", "window_start", "detector_id", "timescale", "flow_id",
            "threat_class", "confidence", "evidence")


def synth_conn_log(path):
    """Return the bundled demo fixture (a real cc-dense slice of the CTU capture-50 conn.log:
    genuine Neris C&C beacons + benign background) if present; otherwise synthesize a minimal
    coordinated beacon. The real fixture is used because the deployment thresholds are tuned on
    real behavior (fast~0.997, deep~0.992) and a toy synthetic beacon does not reach them."""
    fixture = os.path.join(HERE, "examples", "demo_conn.log")
    if os.path.exists(fixture):
        with open(fixture) as f:
            n = sum(1 for ln in f if ln.strip() and not ln.startswith("#"))
        import shutil
        shutil.copyfile(fixture, path)
        return max(n, 0)
    # fallback synthetic (plumbing only)
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
              "duration", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "local_orig"]
    lines = ["#separator \\x09", "#fields\t" + "\t".join(fields)]
    t0 = 1_313_600_000.0
    uid = 0
    rows = []
    # coordinated beacon: 25 hosts -> 147.32.80.9:443 every 45s
    for h in range(25):
        for k in range(28):
            ts = t0 + k * 45.0 + (h % 3)
            rows.append((ts, f"C{uid}", f"147.32.84.{10+h}", 50000 + k, "203.0.113.7", 443,
                         "tcp", 0.20, 6, 360, 5, 300, "T")); uid += 1
    # benign noise: many hosts, one-off varied contacts
    for j in range(400):
        ts = t0 + (j * 3.1)
        rows.append((ts, f"N{uid}", f"147.32.90.{j % 50}", 40000 + j, f"198.51.100.{j % 200}",
                     80 if j % 2 else 53, "tcp" if j % 2 else "udp",
                     1.5, 12, 900, 10, 1200, "T")); uid += 1
    rows.sort(key=lambda r: r[0])
    for r in rows:
        lines.append("\t".join(str(x) for x in r))
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return len(rows)


def check(name, ok, detail=""):
    print(f"  {name:24s} {'PASS' if ok else 'FAIL'}{('  ' + detail) if detail else ''}", flush=True)
    return ok


def main():
    import pandas as pd
    results = []
    tmp = os.path.join(tempfile.gettempdir(), "c2_smoke_conn.log")
    n_syn = synth_conn_log(tmp)

    # 1. model loads + 2. feature schema matches
    ok_load, ok_schema = True, True
    for key, (art, L, S, ts_lbl, did) in DETECTORS.items():
        try:
            b = joblib.load(os.path.join(HERE, art))
            if b["feature_schema"] != EVIDENCE_FEATURES:
                ok_schema = False
            if b["threshold"] is None:
                ok_load = False
        except Exception as e:
            ok_load = False; print("   load error:", e)
    results.append(check("model loads", ok_load))
    results.append(check("feature schema matches", ok_schema, f"{len(EVIDENCE_FEATURES)} features"))

    # 3. Zeek input parses
    df = load_conn(tmp, 0)
    results.append(check("Zeek input parses", len(df) == n_syn, f"{len(df)} flows"))
    origin = pd.Timestamp(df["ts"].min()).floor("1s")

    # 4/5. detectors run  6. alerts generated
    alerts_by = {}
    ran = {"fast": False, "deep": False}
    for key in ("fast", "deep"):
        det = make_detector(key, origin, internal_prefixes=("147.32.",))
        got = []
        for r in df.itertuples(index=False):
            got.extend(det.push(ts=r.ts, orig_h=r.orig_h, resp_h=r.resp_h, resp_p=r.resp_p,
                                proto=r.proto, orig_pkts=r.orig_pkts, resp_pkts=r.resp_pkts,
                                duration=r.duration, orig_ip_bytes=r.orig_ip_bytes,
                                resp_ip_bytes=r.resp_ip_bytes, uid=r.uid))
        got.extend(det.flush())
        alerts_by[key] = got
        ran[key] = (det.n_units_scored > 0 and det.n_state_flows == 0)
    results.append(check("60s detector runs", ran["fast"]))
    results.append(check("300s detector runs", ran["deep"]))
    total_alerts = sum(len(v) for v in alerts_by.values())
    results.append(check("alerts generated", total_alerts > 0,
                         f"fast={len(alerts_by['fast'])} deep={len(alerts_by['deep'])}"))

    # 7. alert schema valid
    schema_ok = True
    for got in alerts_by.values():
        for a in got:
            rec = alert_record(a)
            if any(k not in rec for k in REQUIRED):
                schema_ok = False; break
            if rec["threat_class"] != "C2_BEACONING" or not (0.0 <= rec["confidence"] <= 1.0):
                schema_ok = False; break
            feats = rec["evidence"]["features"]
            if set(feats) != set(EVIDENCE_FEATURES) or "orig_h" in feats:
                schema_ok = False; break
    results.append(check("alert schema valid", schema_ok))

    # 8. bounded state (both detectors drained to 0 after flush already asserted via ran[])
    results.append(check("bounded state", ran["fast"] and ran["deep"], "drains to 0 after flush"))

    print()
    if all(results):
        print("SMOKE TEST: ALL PASS", flush=True)
        sys.exit(0)
    print("SMOKE TEST: FAILURES PRESENT", flush=True)
    sys.exit(1)


if __name__ == "__main__":
    main()
