"""Passive C2-beaconing window feature extractor (7 essential features).

Implements ONLY the essential tier of ``_audit_work/results/FEATURE_SPEC.md``:

    endpoint_host_fanin   F2  distinct internal hosts contacting endpoint e in W (broadcast)
    n_flows               F4  flow count of sequence (h,e) in W
    dst_recurrence        F1  fraction of W's sub-bins in which (h,e) is active
    host_endpoint_fanout  F3  distinct endpoints host h contacts in W (broadcast)
    iat_mean              F6  mean inter-arrival gap of (h,e) in W  [undefined if <1 gap]
    iat_cov               F8  std/mean of gaps (population std, ddof=0)  [undefined if <2 gaps]
    mean_pkts             F10 mean (orig_pkts+resp_pkts) per flow of (h,e) in W

Aggregation unit (FEATURE_SPEC §0):
    endpoint  e = (resp_h, resp_p, proto)      — remote service (grouping key ONLY)
    host      h = orig_h  (local_orig = T)      — internal originator
    window    W = tumbling interval of length Δ — Δ is NOT locked here (caller supplies it)
    vector produced per (h, e, W); fan-in broadcast from (e,W), fan-out from (h,W)

Design guarantees:
  * Destination/host IPs are grouping keys, never feature values -> no IP memorization.
  * Fan-in is scoped to the *active window* and computed from that window's flows only,
    so a later window's contacts can never leak into an earlier window's fan-in.
  * ``extract`` (batch) and ``StreamingWindowExtractor`` (online) share one kernel,
    ``extract_window`` -> train/inference parity by construction.
  * ``window`` is a REQUIRED argument (no default): the audit forbids locking Δ, so the
    extractor refuses to invent one.
"""
from __future__ import annotations

from collections import defaultdict

import numpy as np
import pandas as pd

from .sources import ensure_datetime

# ---- schema ---------------------------------------------------------------

FEATURE_COLUMNS = [
    "endpoint_host_fanin",   # F2
    "n_flows",               # F4
    "dst_recurrence",        # F1
    "host_endpoint_fanout",  # F3
    "iat_mean",              # F6
    "iat_cov",               # F8
    "mean_pkts",             # F10
]
KEY_COLUMNS = ["window_start", "orig_h", "resp_h", "resp_p", "proto"]

# minimum number of inter-arrival gaps for each timing statistic to be *defined*.
# n flows -> n-1 gaps. mean needs >=1 gap; a coefficient of variation needs >=2.
MIN_GAPS_FOR_IAT_MEAN = 1
MIN_GAPS_FOR_COV = 2

DEFAULT_SUBBINS = 10   # B for dst_recurrence; NOT a locked hyperparameter, just a default
NO_PORT = -1           # sentinel for missing/NaN resp_p so endpoint keys stay hashable

_INT_FEATURES = ["endpoint_host_fanin", "n_flows", "host_endpoint_fanout"]
_FLOAT_FEATURES = ["dst_recurrence", "iat_mean", "iat_cov", "mean_pkts"]


# ---- inter-arrival gaps (verbatim from audit notebook §"iat_seconds") -----

def iat_seconds(ts_series) -> np.ndarray:
    """Resolution-independent inter-arrival gaps (seconds), sorted, non-negative.

    Identical to the audit notebook: sort timestamps, diff, convert with
    ``.dt.total_seconds()`` (NEVER ``astype(int64)`` — that would leak the datetime
    unit). Returns a numpy array of length ``n-1`` (empty for n<2).
    """
    t = pd.Series(ts_series).dropna().sort_values()
    d = t.diff().dropna().dt.total_seconds().values
    return d[d >= 0]


# ---- helpers --------------------------------------------------------------

def _col_num(df: pd.DataFrame, col: str) -> pd.Series:
    """Numeric column if present, else zeros aligned to ``df`` (packets default to 0)."""
    if col in df.columns:
        return pd.to_numeric(df[col], errors="coerce")
    return pd.Series(0.0, index=df.index, dtype="float64")


def _prepare(df: pd.DataFrame, internal_only: bool = True) -> pd.DataFrame:
    """Normalize working columns and enforce internal->remote direction.

    Row-wise only (no cross-row aggregation), so applying it to a subset equals
    applying it to the whole frame then slicing — the property that makes the
    streaming path bit-parity with the batch path.
    """
    d = df.copy()
    d["ts"] = ensure_datetime(d["ts"])
    d = d.loc[d["ts"].notna()].copy()

    # direction filter: drop ONLY rows explicitly marked external (local_orig == False).
    # NA / missing local_orig is kept (binetflow has no such column).
    if internal_only and "local_orig" in d.columns:
        is_false = d["local_orig"].eq(False).fillna(False).astype(bool)
        d = d.loc[~is_false].copy()

    d["orig_h"] = d["orig_h"].astype(str)
    d["resp_h"] = d["resp_h"].astype(str)
    d["resp_p"] = pd.to_numeric(d["resp_p"], errors="coerce").fillna(NO_PORT).astype("int64")
    d["proto"] = (
        d["proto"].astype(str).str.lower().str.strip()
        .replace({"nan": "unknown", "": "unknown", "none": "unknown", "<na>": "unknown"})
    )
    d["_pkts"] = _col_num(d, "orig_pkts").fillna(0) + _col_num(d, "resp_pkts").fillna(0)
    return d


def _empty_frame() -> pd.DataFrame:
    """Empty result with the exact schema/dtypes of a populated result."""
    cols = {
        "window_start": pd.Series(dtype="datetime64[ns]"),
        "orig_h": pd.Series(dtype="object"),
        "resp_h": pd.Series(dtype="object"),
        "resp_p": pd.Series(dtype="int64"),
        "proto": pd.Series(dtype="object"),
        "endpoint_host_fanin": pd.Series(dtype="int64"),
        "n_flows": pd.Series(dtype="int64"),
        "dst_recurrence": pd.Series(dtype="float64"),
        "host_endpoint_fanout": pd.Series(dtype="int64"),
        "iat_mean": pd.Series(dtype="float64"),
        "iat_cov": pd.Series(dtype="float64"),
        "mean_pkts": pd.Series(dtype="float64"),
    }
    return pd.DataFrame(cols)


def _cast(df: pd.DataFrame) -> pd.DataFrame:
    """Fix output dtypes: counts -> int64, ratios/means -> float64 (NaN-capable)."""
    df = df.copy()
    for c in _INT_FEATURES:
        df[c] = df[c].astype("int64")
    for c in _FLOAT_FEATURES:
        df[c] = df[c].astype("float64")
    return df


# ---- the kernel: one closed window ---------------------------------------

def extract_window(win_df: pd.DataFrame, window_start, window_len, subbins=DEFAULT_SUBBINS):
    """Feature rows for ONE already-closed window.

    ``win_df`` holds every flow whose ``window_start`` == ``window_start`` (already
    ``_prepare``-d: normalized keys, datetime ``ts``, ``_pkts``). This is the single
    kernel shared by the batch and streaming paths.

    Fan-in / fan-out are computed from the flows *in this window only*: because a
    tumbling window is emitted only once it has closed, no future-window contact can
    enter these counts (the causal-fan-in guarantee).
    """
    win_df = win_df  # kept for readability; caller passes a prepared frame
    if "_pkts" not in win_df.columns:                       # tolerate a raw direct call
        win_df = win_df.copy()
        win_df["_pkts"] = _col_num(win_df, "orig_pkts").fillna(0) + _col_num(win_df, "resp_pkts").fillna(0)
    if not pd.api.types.is_datetime64_any_dtype(win_df["ts"]):
        win_df = win_df.copy()
        win_df["ts"] = ensure_datetime(win_df["ts"])

    if len(win_df) == 0:
        return _empty_frame()

    # --- cross-sequence aggregates within this window (counts only, no identity) ---
    hosts_per_ep = defaultdict(set)   # endpoint (resp_h,resp_p,proto) -> set of hosts
    eps_per_host = defaultdict(set)   # host orig_h               -> set of endpoints
    for h, rh, rp, pr in zip(win_df["orig_h"], win_df["resp_h"], win_df["resp_p"], win_df["proto"]):
        e = (rh, rp, pr)
        hosts_per_ep[e].add(h)
        eps_per_host[h].add(e)

    binsize = window_len.total_seconds() / subbins

    rows = []
    for (h, rh, rp, pr), g in win_df.groupby(
        ["orig_h", "resp_h", "resp_p", "proto"], dropna=False, sort=False
    ):
        e = (rh, rp, pr)
        n = len(g)

        gaps = iat_seconds(g["ts"])
        ng = len(gaps)
        gmean = float(gaps.mean()) if ng else np.nan
        iat_mean = gmean if ng >= MIN_GAPS_FOR_IAT_MEAN else np.nan
        # population std (numpy default ddof=0) to match the audit's CoV numbers
        iat_cov = (
            float(gaps.std() / gmean)
            if (ng >= MIN_GAPS_FOR_COV and gmean and gmean > 0)
            else np.nan
        )

        mean_pkts = float(g["_pkts"].mean())

        # dst_recurrence: fraction of the window's B sub-bins that contain a flow
        off = (g["ts"] - window_start).dt.total_seconds().to_numpy()
        idx = np.clip(np.floor(off / binsize), 0, subbins - 1).astype(int)
        dst_recurrence = len(set(idx.tolist())) / subbins

        rows.append((
            window_start, h, rh, rp, pr,
            len(hosts_per_ep[e]),   # endpoint_host_fanin
            n,                      # n_flows
            dst_recurrence,         # dst_recurrence
            len(eps_per_host[h]),   # host_endpoint_fanout
            iat_mean,               # iat_mean
            iat_cov,                # iat_cov
            mean_pkts,              # mean_pkts
        ))

    return pd.DataFrame(rows, columns=KEY_COLUMNS + FEATURE_COLUMNS)


# ---- batch entrypoint -----------------------------------------------------

def extract(conns: pd.DataFrame, window, subbins=DEFAULT_SUBBINS, internal_only=True) -> pd.DataFrame:
    """Extract window features from a batch of normalized flows.

    Parameters
    ----------
    conns : DataFrame with NORMALIZED_COLUMNS (from ``c2beacon.sources``).
    window : pandas frequency/offset string for the tumbling window length Δ
        (e.g. ``"1h"``, ``"5min"``, ``"60s"``). REQUIRED — the audit forbids locking Δ,
        so there is deliberately no default.
    subbins : sub-bin count B for ``dst_recurrence`` (default, not locked).
    internal_only : drop flows explicitly marked ``local_orig == False``.
    """
    d = _prepare(conns, internal_only)
    if d.empty:
        return _empty_frame()

    window_len = pd.Timedelta(window)
    d = d.assign(window_start=d["ts"].dt.floor(window))

    frames = [
        extract_window(wdf, ws, window_len, subbins)
        for ws, wdf in d.groupby("window_start", sort=True)
    ]
    frames = [f for f in frames if len(f)]
    if not frames:
        return _empty_frame()
    return _cast(pd.concat(frames, ignore_index=True))


# ---- streaming entrypoint -------------------------------------------------

class StreamingWindowExtractor:
    """Online tumbling-window extractor sharing ``extract_window`` with :func:`extract`.

    Assumes flows are pushed in non-decreasing ``ts`` order (a real capture stream).
    A window is emitted only once a later window opens (``push`` returns it) or on
    :meth:`flush` — never before it has closed, so fan-in stays causal.

    Because it reuses ``_prepare`` + ``extract_window``, its output is identical to the
    batch path on the same input (verified by ``test_streaming_batch_parity``).
    """

    def __init__(self, window, subbins=DEFAULT_SUBBINS, internal_only=True):
        self.window = window
        self.window_len = pd.Timedelta(window)
        self.subbins = subbins
        self.internal_only = internal_only
        self._buffer = {}        # window_start (Timestamp) -> list of raw row dicts
        self._watermark = None   # latest window_start seen

    def push(self, ts, orig_h, resp_h, resp_p=None, proto=None,
             orig_pkts=0, resp_pkts=0, local_orig=None) -> pd.DataFrame:
        """Ingest one flow; return any windows that closed as a result (may be empty)."""
        if isinstance(ts, (int, float)) and not isinstance(ts, bool):
            ts = pd.Timestamp(ts, unit="s")          # epoch seconds (Zeek ts)
        else:
            ts = pd.Timestamp(ts)
        if pd.isna(ts):
            return _empty_frame()

        ws = ts.floor(self.window)
        self._buffer.setdefault(ws, []).append({
            "ts": ts, "orig_h": orig_h, "resp_h": resp_h, "resp_p": resp_p,
            "proto": proto, "orig_pkts": orig_pkts, "resp_pkts": resp_pkts,
            "local_orig": local_orig,
        })
        if self._watermark is None or ws > self._watermark:
            self._watermark = ws

        # every buffered window strictly older than the current one has now closed
        ready = sorted(w for w in self._buffer if w < ws)
        return self._emit_many(ready)

    def flush(self) -> pd.DataFrame:
        """Emit all remaining buffered windows (call once the stream ends)."""
        return self._emit_many(sorted(self._buffer))

    def _emit_many(self, window_starts) -> pd.DataFrame:
        frames = [self._emit(ws) for ws in window_starts]
        frames = [f for f in frames if len(f)]
        return pd.concat(frames, ignore_index=True) if frames else _empty_frame()

    def _emit(self, ws) -> pd.DataFrame:
        rows = self._buffer.pop(ws)
        prepared = _prepare(pd.DataFrame(rows), self.internal_only)
        if prepared.empty:
            return _empty_frame()
        return _cast(extract_window(prepared, ws, self.window_len, self.subbins))


# ---- model-facing view ----------------------------------------------------

def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Return ONLY the numeric feature columns — no keys, no IPs, no timestamps.

    This is what a model consumes. It structurally cannot leak ``resp_h``/``orig_h``
    identity or ``window_start`` because those live in KEY_COLUMNS, not here.
    """
    return df.loc[:, FEATURE_COLUMNS].copy()
