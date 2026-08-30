"""Streaming ext13 C2-beaconing detector (production) for BOTH timescales.

Subclasses the FROZEN ``StreamingBeaconDetector`` (rolling-state, eviction, window-close
logic all inherited UNCHANGED) and swaps only:
  * ``push`` — additionally carries passive ``duration`` and IP-byte metadata per flow;
  * ``_close_window`` — scores with the 13-feature ext kernel + EXT_FEATURE_COLUMNS.

Nothing in the frozen 7-feature detector is modified. Instantiate with the deployment
geometry: fast = window_s=60, stride_s=10 ; deep = window_s=300, stride_s=60. The two
run as INDEPENDENT instances — no score fusion. Both are passive, read-only, metadata-only,
bounded-state; Zeek uid and endpoint IPs are alert CONTEXT only, never model features.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .streaming import (StreamingBeaconDetector, Alert, _num, _norm_port,
                        _norm_proto, _scalar_ts)
from .features_ext import extract_window_ext, EXT_FEATURE_COLUMNS


class StreamingBeaconDetectorExt(StreamingBeaconDetector):
    """Incremental detector for the shipped ext13 model. Push flows in ~time order."""

    def push(self, ts, orig_h, resp_h, resp_p, proto, orig_pkts=0, resp_pkts=0,
             duration=0.0, orig_ip_bytes=0.0, resp_ip_bytes=0.0,
             uid=None, local_orig=None):
        self.n_pushed += 1
        t = _scalar_ts(ts)
        if t is None or pd.isna(t):
            return []
        if local_orig is False:
            return []
        oh = str(orig_h)
        if self.internal_prefixes is not None and not oh.startswith(self.internal_prefixes):
            return self._advance(t.value / 1e9)
        row = dict(ts=t, orig_h=oh, resp_h=str(resp_h),
                   resp_p=_norm_port(resp_p), proto=_norm_proto(proto),
                   _pkts=float(np.nan_to_num(_num(orig_pkts)) + np.nan_to_num(_num(resp_pkts))),
                   _dur=float(np.nan_to_num(_num(duration))),
                   _bytes=float(np.nan_to_num(_num(orig_ip_bytes)) + np.nan_to_num(_num(resp_ip_bytes))),
                   uid=(str(uid) if uid is not None else None))
        e = t.value / 1e9
        if not self._ts_epoch or e >= self._ts_epoch[-1]:
            self._ts_epoch.append(e); self._ts.append(t); self._rows.append(row)
        else:
            import bisect
            i = bisect.bisect_right(self._ts_epoch, e)
            self._ts_epoch.insert(i, e); self._ts.insert(i, t); self._rows.insert(i, row)
        self.n_kept += 1
        return self._advance(e)

    def _close_window(self, k, s_epoch, end_epoch):
        self.n_windows_closed += 1
        rows = self._window_slice(s_epoch, end_epoch)
        if not rows:
            return []
        s_ts = self.origin + pd.Timedelta(seconds=k * self.stride_s)
        win_df = pd.DataFrame(rows)
        feats = extract_window_ext(win_df, s_ts, self.window_len, self.subbins)
        if len(feats) == 0:
            return []
        self.n_units_scored += len(feats)
        if self.feature_only:
            self.emitted.append(feats)
            return []

        proba = self.model.predict_proba(feats[EXT_FEATURE_COLUMNS])[:, 1]
        hits = np.flatnonzero(proba >= self.threshold)
        if len(hits) == 0:
            return []

        uid_by_key: dict = {}
        for r in rows:
            uid_by_key.setdefault((r["orig_h"], r["resp_h"], r["resp_p"], r["proto"]), []).append(r["uid"])

        t_emit = pd.Timestamp(end_epoch, unit="s", tz="UTC").tz_localize(None)
        ws_iso = s_ts.isoformat()
        alerts: list = []
        for i in hits:
            row = feats.iloc[int(i)]
            key = (row["orig_h"], row["resp_h"], int(row["resp_p"]), row["proto"])
            uids = [u for u in uid_by_key.get(key, []) if u is not None]
            evidence = {c: (None if pd.isna(row[c]) else float(row[c])) for c in EXT_FEATURE_COLUMNS}
            evidence.update(orig_h=row["orig_h"], resp_h=row["resp_h"],
                            resp_p=int(row["resp_p"]), proto=row["proto"],
                            detector_id=self.detector_id, timescale=self.timescale,
                            n_contributing_flows=len(uid_by_key.get(key, [])))
            alerts.append(Alert(
                timestamp=t_emit.isoformat(), window_start=ws_iso,
                flow_id=uids, threat_class=self.threat_class,
                confidence=float(proba[i]), evidence=evidence))
        self.n_alerts += len(alerts)
        return alerts

    # convenience labels for the two timescales (set by caller; defaults from geometry)
    @property
    def detector_id(self):
        return getattr(self, "_detector_id", f"c2_{self.window_s}s_{self.stride_s}s")

    @detector_id.setter
    def detector_id(self, v):
        self._detector_id = v

    @property
    def timescale(self):
        return getattr(self, "_timescale",
                       "c2_fast_60s" if self.window_s == 60 else
                       ("c2_deep_300s" if self.window_s == 300 else f"c2_{self.window_s}s"))

    @timescale.setter
    def timescale(self, v):
        self._timescale = v
