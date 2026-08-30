# C2 Beaconing Detector — Integration Guide

Passive, read-only, streaming detector for the **C2_BEACONING** threat class.
Metadata-only (no payload, no decryption). Drops into the pipeline as one more
detector emitting the standardized alert schema.

## What it consumes / emits
- **In:** native Zeek `conn.log` records, streamed incrementally.
- **Out:** JSONL alerts conforming to `schema/alert_schema.json`, `threat_class="C2_BEACONING"`.
- **No return path, no blocking, bounded state, bounded alert latency.**

## Two independent detectors (no score fusion)
| detector_id  | role              | window/stride | alert latency |
|--------------|-------------------|---------------|---------------|
| c2_60s_10s   | primary (live)    | 60s / 10s     | ≤60s          |
| c2_300s_60s  | secondary (slow)  | 300s / 60s    | ≤300s         |

Run both as separate instances; do not combine their scores.

## Option A — subprocess / replay (simplest)
```bash
python run_detector.py --conn <path/to/conn.log> --out alerts.jsonl --detector both \
  --internal-prefix 147.32.
```
Set `--internal-prefix` to YOUR monitored internal prefixes (comma-separate multiple),
or omit to score all originators.

## Option B — embed the streaming class (for a live tap)
```python
import joblib
from c2beacon.streaming_ext import StreamingBeaconDetectorExt

b = joblib.load("models/c2_detector_60s_10s_ext13.joblib")
det = StreamingBeaconDetectorExt(
    model=b["pipeline"], threshold=b["threshold"], origin=first_flow_ts,
    window_s=60, stride_s=10, subbins=10,
    internal_prefixes=("147.32.",),   # <-- set to your network
)
for flow in zeek_stream:              # dict per conn.log record
    for alert in det.push(flow):      # yields Alert objects as windows close
        emit(alert.to_dict())
for alert in det.flush():             # drain at shutdown
    emit(alert.to_dict())
```
`det.n_state_flows()` reports live buffered flows (proves bounded state; drains to 0 after flush).

## Integration checklist
1. **Threshold:** always load `bundle["threshold"]` from the artifact. Never hardcode.
2. **Internal prefixes:** set to the monitored enclave's ranges — this is the only site-specific config.
3. **IPs/ports/uids are context only**, never model features. Do not add identity features.
4. **Required Zeek fields:** ts, id.orig_h, id.resp_h, id.resp_p, proto, orig_pkts, resp_pkts,
   duration, orig_ip_bytes, resp_ip_bytes, uid.
5. Validate emitted alerts against `schema/alert_schema.json` in CI.
6. Run `python qa_smoke_test.py` after any dependency bump — 8 gates must stay green.

See `config/deployment.json` for the machine-readable spec and `MODEL_CARD.md` for metrics.
