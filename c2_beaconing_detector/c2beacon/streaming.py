"""Streaming 60s/10s C2-beaconing detector (SIH live geometry).

A genuinely incremental detector over a continuously-updated stream of Zeek ``conn.log``
events. It is PASSIVE and DETECTION-ONLY: it reads flow metadata, never queries or modifies
any source, never inspects payload, never decrypts. It maintains only the rolling state
required for a 60-second sliding window advanced on a 10-second stride, and emits a
prediction + standardized alerts every stride.

Feature parity: the detector calls the SAME ``extract_window`` kernel used by batch training,
on exactly the flows in each closed window ``[t_emit-60, t_emit)``. The batch geometry builder
(``vectorized_units``) and ``extract_window`` are byte-parity-checked, so streaming features
are transitively identical to training features.

State bound: a flow is retained only while some not-yet-closed window can still contain it;
once the watermark passes ``flow_ts + window_s`` the flow is evicted. Memory is O(flows in the
last ~window_s seconds), independent of capture length.

Alert schema (per flagged unit):
    timestamp     -- ISO close time of the window that produced the alert (t_emit)
    window_start  -- ISO start of the 60s window
    flow_id       -- Zeek uid(s) of the contributing flows (list); uid is CONTEXT, never a feature
    threat_class  -- "C2_BEACONING"
    confidence    -- model probability for the unit
    evidence      -- the 7 model features (iat_mean/iat_cov null-capable) + endpoint/host context

``uid`` and endpoint IPs appear ONLY as alert context, never as model inputs.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field, asdict
from typing import Any

import numpy as np
import pandas as pd

from .features import extract_window, FEATURE_COLUMNS, KEY_COLUMNS, NO_PORT, DEFAULT_SUBBINS
from .sources import ensure_datetime

TIMING_FEATURES = ("iat_mean", "iat_cov")


@dataclass
class Alert:
    timestamp: str
    window_start: str
    flow_id: list
    threat_class: str
    confidence: float
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _norm_proto(p: Any) -> str:
    s = str(p).lower().strip()
    return {"nan": "unknown", "": "unknown", "none": "unknown", "<na>": "unknown"}.get(s, s)


def _norm_port(p: Any) -> int:
    try:
        v = int(float(p))
        return v
    except Exception:
        return NO_PORT


class StreamingBeaconDetector:
    """Incremental sliding-window detector. Push flows in (near) time order; get alerts back."""

    def __init__(self, model=None, threshold: float = 0.5, *, origin,
                 window_s: int = 60, stride_s: int = 10, subbins: int = DEFAULT_SUBBINS,
                 threat_class: str = "C2_BEACONING",
                 internal_prefixes: tuple | None = ("147.32.",),
                 lateness_s: float = 0.0, feature_only: bool = False):
        self.model = model
        self.threshold = float(threshold)
        self.origin = pd.Timestamp(origin)
        self.window_s = int(window_s)
        self.stride_s = int(stride_s)
        self.window_len = pd.Timedelta(seconds=window_s)
        self.subbins = int(subbins)
        self.threat_class = threat_class
        self.internal_prefixes = internal_prefixes
        self.lateness_s = float(lateness_s)
        self.feature_only = feature_only

        # rolling state: parallel arrays kept sorted by ts (bisect on _ts_epoch)
        self._ts: list = []          # pd.Timestamp
        self._ts_epoch: list = []    # float seconds (for bisect + eviction)
        self._rows: list = []        # dict of canonical flow fields (+ uid)
        self._watermark = -np.inf    # max epoch seen
        self._next_k = 0             # next window index to close
        self._origin_epoch = self.origin.value / 1e9
        # metrics
        self.n_pushed = 0
        self.n_kept = 0
        self.n_windows_closed = 0
        self.n_units_scored = 0
        self.n_alerts = 0
        self.emitted: list = []      # feature frames, populated only in feature_only mode

    # ------------------------------------------------------------------ ingest
    def push(self, ts, orig_h, resp_h, resp_p, proto, orig_pkts=0, resp_pkts=0,
             uid=None, local_orig=None) -> list[Alert]:
        """Ingest one flow record; return any alerts from windows this event closes."""
        self.n_pushed += 1
        t = _scalar_ts(ts)
        if t is None or pd.isna(t):
            return []
        # passive direction filter (internal originator proxy); explicit external => drop
        if local_orig is False:
            return []
        oh = str(orig_h)
        if self.internal_prefixes is not None and not oh.startswith(self.internal_prefixes):
            # not an internal originator -> not a beaconing source we model; still advances time
            return self._advance(t.value / 1e9)
        row = dict(ts=t, orig_h=oh, resp_h=str(resp_h),
                   resp_p=_norm_port(resp_p), proto=_norm_proto(proto),
                   _pkts=float(np.nan_to_num(_num(orig_pkts)) + np.nan_to_num(_num(resp_pkts))),
                   uid=(str(uid) if uid is not None else None))
        e = t.value / 1e9
        # fast path for the common in-order stream: append is O(1) vs O(n) list.insert
        if not self._ts_epoch or e >= self._ts_epoch[-1]:
            self._ts_epoch.append(e)
            self._ts.append(t)
            self._rows.append(row)
        else:
            i = bisect.bisect_right(self._ts_epoch, e)
            self._ts_epoch.insert(i, e)
            self._ts.insert(i, t)
            self._rows.insert(i, row)
        self.n_kept += 1
        return self._advance(e)

    def _advance(self, e: float) -> list[Alert]:
        if e > self._watermark:
            self._watermark = e
        alerts: list[Alert] = []
        # close every window whose end (+lateness) is <= watermark
        while True:
            s_epoch = self._origin_epoch + self._next_k * self.stride_s
            end_epoch = s_epoch + self.window_s
            if end_epoch + self.lateness_s > self._watermark:
                break
            alerts.extend(self._close_window(self._next_k, s_epoch, end_epoch))
            self._next_k += 1
            self._evict(self._origin_epoch + self._next_k * self.stride_s)
        return alerts

    def flush(self) -> list[Alert]:
        """Close every remaining open window at end-of-stream (bounded catch-up)."""
        # advancing the watermark far past the last flow closes all pending windows
        if not np.isfinite(self._watermark):
            return []
        return self._advance(self._watermark + self.window_s + self.stride_s + 1.0)

    def _window_slice(self, s_epoch: float, end_epoch: float):
        lo = bisect.bisect_left(self._ts_epoch, s_epoch)
        hi = bisect.bisect_left(self._ts_epoch, end_epoch)   # [s, end)
        return self._rows[lo:hi]

    def _close_window(self, k, s_epoch, end_epoch) -> list[Alert]:
        self.n_windows_closed += 1
        rows = self._window_slice(s_epoch, end_epoch)
        if not rows:
            return []
        s_ts = self.origin + pd.Timedelta(seconds=k * self.stride_s)
        win_df = pd.DataFrame(rows)
        feats = extract_window(win_df, s_ts, self.window_len, self.subbins)
        if len(feats) == 0:
            return []
        self.n_units_scored += len(feats)
        if self.feature_only:
            self.emitted.append(feats)
            return []

        proba = self.model.predict_proba(feats[FEATURE_COLUMNS])[:, 1]
        hits = np.flatnonzero(proba >= self.threshold)
        if len(hits) == 0:
            return []

        # map each flagged unit back to its contributing Zeek uids (context only)
        uid_by_key: dict = {}
        for r in rows:
            uid_by_key.setdefault((r["orig_h"], r["resp_h"], r["resp_p"], r["proto"]), []).append(r["uid"])

        t_emit = pd.Timestamp(end_epoch, unit="s", tz="UTC").tz_localize(None)
        ws_iso = s_ts.isoformat()
        alerts: list[Alert] = []
        for i in hits:
            row = feats.iloc[int(i)]
            key = (row["orig_h"], row["resp_h"], int(row["resp_p"]), row["proto"])
            uids = [u for u in uid_by_key.get(key, []) if u is not None]
            evidence = {c: (None if pd.isna(row[c]) else float(row[c])) for c in FEATURE_COLUMNS}
            evidence.update(orig_h=row["orig_h"], resp_h=row["resp_h"],
                            resp_p=int(row["resp_p"]), proto=row["proto"],
                            n_contributing_flows=len(uid_by_key.get(key, [])))
            alerts.append(Alert(
                timestamp=t_emit.isoformat(), window_start=ws_iso,
                flow_id=uids, threat_class=self.threat_class,
                confidence=float(proba[i]), evidence=evidence))
        self.n_alerts += len(alerts)
        return alerts

    def _evict(self, keep_from_epoch: float):
        # a flow at ts belongs to a window with start s iff s <= ts; the earliest still-open
        # window starts at keep_from_epoch, so any flow with ts < keep_from_epoch is dead.
        cut = bisect.bisect_left(self._ts_epoch, keep_from_epoch)
        if cut > 0:
            del self._ts_epoch[:cut]
            del self._ts[:cut]
            del self._rows[:cut]

    @property
    def n_state_flows(self) -> int:
        return len(self._rows)


def _num(x):
    try:
        return float(x)
    except Exception:
        return 0.0


def _scalar_ts(ts):
    """Normalize one timestamp to a tz-naive pd.Timestamp (parity with ensure_datetime).

    Fast per-event path (no Series construction): numeric scalars are epoch SECONDS
    (Zeek ``ts`` semantics); datetime-likes pass through pd.Timestamp. Returns None on
    unparseable input.
    """
    if isinstance(ts, (int, float, np.integer, np.floating)) and not isinstance(ts, bool):
        if ts != ts:  # NaN
            return None
        return pd.Timestamp(float(ts), unit="s")
    try:
        t = pd.Timestamp(ts)
    except Exception:
        return None
    return None if pd.isna(t) else (t.tz_localize(None) if t.tzinfo is not None else t)
