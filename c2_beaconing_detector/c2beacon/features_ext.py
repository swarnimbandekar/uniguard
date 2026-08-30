"""Extended (13-feature) passive C2-beaconing window kernel — PRODUCTION detector.

The frozen 7-feature kernel (``features.extract_window``) is UNCHANGED. This module
adds ONLY the 6 behavioral features that the shipped ``ext13`` HistGradientBoosting model
consumes, reusing the frozen kernel verbatim for the base 7 so those stay byte-identical
to training/streaming parity guarantees:

    base 7 (frozen kernel):  endpoint_host_fanin, n_flows, dst_recurrence,
                             host_endpoint_fanout, iat_mean, iat_cov, mean_pkts
    + 6 new (this module):   iat_madn        robust timing jitter  MAD(gaps)/median(gap)
                             dur_mean         mean connection duration (s)
                             dur_cov          duration consistency   std(dur)/mean(dur)
                             pkts_cov         packet consistency      std(pkts)/mean(pkts)
                             bytes_mean       mean IP bytes / flow
                             host_flow_share  n_flows(seq) / total flows of host in window

All 6 are windowed aggregates over exactly the same closed-window flow set the frozen
kernel uses -> streaming-compatible by construction and byte-parity with the batch
training builder ``build_c2_model.build_units_ext`` (verified by verify_ext_streaming.py).

Duration/bytes come from native Zeek ``conn.log`` (``duration``, ``orig_ip_bytes`` +
``resp_ip_bytes``). They are passive metadata; no payload/DPI. Endpoint/host IPs remain
grouping keys ONLY, never feature values.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .features import extract_window, FEATURE_COLUMNS, KEY_COLUMNS, iat_seconds

NEW_FEATURE_COLUMNS = ["iat_madn", "dur_mean", "dur_cov", "pkts_cov", "bytes_mean",
                       "host_flow_share"]
EXT_FEATURE_COLUMNS = FEATURE_COLUMNS + NEW_FEATURE_COLUMNS
# NaN-prone (undefined for too few flows/gaps) -> the model's imputer handles these
EXT_NAN_PRONE = ("iat_mean", "iat_cov", "iat_madn", "dur_cov", "pkts_cov")


def extract_window_ext(win_df, window_start, window_len, subbins=10):
    """13-feature rows for ONE already-closed window.

    ``win_df`` must carry the frozen kernel's inputs plus per-flow ``_dur`` and ``_bytes``.
    Base 7 come from the UNCHANGED frozen kernel; the 6 extras mirror the training builder
    exactly (pandas ddof=1 for dur/pkts CoV; population math for iat_* lives in the frozen
    kernel). Returned column order == EXT_FEATURE_COLUMNS after the key columns.
    """
    base = extract_window(win_df, window_start, window_len, subbins)
    if len(base) == 0:
        return base.reindex(columns=KEY_COLUMNS + EXT_FEATURE_COLUMNS)

    d = win_df
    if "_dur" not in d.columns:
        d = d.copy(); d["_dur"] = 0.0
    if "_bytes" not in d.columns:
        d = d.copy(); d["_bytes"] = 0.0

    # total flows per host in this window (denominator for host_flow_share)
    host_total = d.groupby("orig_h").size()

    extra = []
    for (h, rh, rp, pr), g in d.groupby(["orig_h", "resp_h", "resp_p", "proto"],
                                        dropna=False, sort=False):
        n = len(g)
        gaps = iat_seconds(g["ts"])
        ng = len(gaps)
        if ng >= 2:
            gmed = float(np.median(gaps))
            iat_madn = float(np.median(np.abs(gaps - gmed)) / gmed) if gmed > 0 else np.nan
        else:
            iat_madn = np.nan
        dur = pd.to_numeric(g["_dur"], errors="coerce")
        dur_mean = float(dur.mean())
        dur_cov = float(dur.std() / dur_mean) if (n >= 2 and dur_mean > 0) else np.nan  # ddof=1
        pk = pd.to_numeric(g["_pkts"], errors="coerce")
        pk_mean = float(pk.mean())
        pkts_cov = float(pk.std() / pk_mean) if (n >= 2 and pk_mean > 0) else np.nan  # ddof=1
        bytes_mean = float(pd.to_numeric(g["_bytes"], errors="coerce").mean())
        host_flow_share = float(n / host_total[h]) if host_total[h] else np.nan
        extra.append((h, rh, rp, pr, iat_madn, dur_mean, dur_cov, pkts_cov,
                      bytes_mean, host_flow_share))

    ext = pd.DataFrame(extra, columns=["orig_h", "resp_h", "resp_p", "proto"]
                       + NEW_FEATURE_COLUMNS)
    out = base.merge(ext, on=["orig_h", "resp_h", "resp_p", "proto"], how="left")
    return out.loc[:, KEY_COLUMNS + EXT_FEATURE_COLUMNS]
