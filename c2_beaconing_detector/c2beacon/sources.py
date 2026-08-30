"""Passive-flow source normalizers -> one common schema for the extractor.

The extractor consumes a single **normalized** schema so that the *same* code path
serves training (labeled bidirectional NetFlow / binetflow) and inference (Zeek
``conn.log``). This is the "one schema, identical vectors" requirement from the
README and FEATURE_SPEC — verified by the source-parity test.

NORMALIZED_COLUMNS
------------------
    ts         datetime64 (any resolution) OR epoch seconds -> normalized to datetime64[ns]
    orig_h     str   internal originator IP        (Zeek id.orig_h / binetflow SrcAddr)
    resp_h     str   remote responder IP           (Zeek id.resp_h / binetflow DstAddr)
    resp_p     float remote port (NaN allowed)     (Zeek id.resp_p / binetflow Dport)
    proto      str   transport, lower-cased        (Zeek proto     / binetflow Proto)
    orig_pkts  float packets orig->resp            (Zeek orig_pkts / binetflow SrcPkts)
    resp_pkts  float packets resp->orig            (Zeek resp_pkts / binetflow DstPkts)
    local_orig bool  originator is internal (opt)  (Zeek local_orig; absent for binetflow)

Only passive flow metadata is mapped. No payload/DPI field (``service``, JA3, …) and
**no label** are ever carried into the extractor — label leakage is impossible by
construction, and the ``service`` field (unreliable under CTU-13-Extended truncation)
is deliberately excluded (FEATURE_SPEC §7).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

NORMALIZED_COLUMNS = [
    "ts", "orig_h", "resp_h", "resp_p", "proto", "orig_pkts", "resp_pkts", "local_orig",
]


def ensure_datetime(series) -> pd.Series:
    """Resolution-independent timestamp normalization -> datetime64[ns].

    Mirrors the audit's rule (notebook §6): never ``astype(int64)`` a datetime (that
    leaks the underlying unit — pandas often parses to ``[us]``, not ``[ns]``). A
    datetime column is returned as-is (its resolution is preserved and handled later
    by ``.dt.total_seconds()``); a numeric/string column is read as **epoch seconds**
    (Zeek ``conn.log`` ``ts``) and converted with ``unit="s"``.
    """
    s = pd.Series(series)
    if pd.api.types.is_datetime64_any_dtype(s):
        return pd.to_datetime(s)
    v = pd.to_numeric(s, errors="coerce")
    return pd.to_datetime(v, unit="s")


def _num(df: pd.DataFrame, col: str) -> pd.Series:
    """Numeric column if present, else an all-NaN column aligned to ``df``."""
    if col in df.columns:
        return pd.to_numeric(df[col], errors="coerce")
    return pd.Series(np.nan, index=df.index, dtype="float64")


def _to_bool(x):
    s = str(x).strip().lower()
    if s in ("t", "true", "1"):
        return True
    if s in ("f", "false", "0"):
        return False
    return pd.NA


def read_zeek_conn_log(path: str) -> pd.DataFrame:
    """Read a Zeek/Bro ``conn.log`` (TSV) into a raw DataFrame of strings.

    Faithful to the audit notebook §8 reader: honors ``#separator`` / ``#fields``
    headers and skips all ``#`` comment lines. Cells are left as raw strings ('-' for
    unset); typing/mapping happens in :func:`normalize_zeek_conn`.
    """
    fields, sep = None, "\t"
    rows = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("#separator"):
                sep = line.strip().split(" ", 1)[1].encode().decode("unicode_escape")
            elif line.startswith("#fields"):
                fields = line.rstrip("\n").split(sep)[1:]
            elif not line.startswith("#"):
                rows.append(line.rstrip("\n").split(sep))
    return pd.DataFrame(rows, columns=fields)


def normalize_zeek_conn(raw: pd.DataFrame) -> pd.DataFrame:
    """Map a raw Zeek ``conn.log`` frame to NORMALIZED_COLUMNS (inference source)."""
    n = pd.DataFrame(index=raw.index)
    n["ts"] = ensure_datetime(raw["ts"])
    n["orig_h"] = raw["id.orig_h"].astype(str)
    n["resp_h"] = raw["id.resp_h"].astype(str)
    n["resp_p"] = _num(raw, "id.resp_p")
    n["proto"] = raw["proto"].astype(str).str.lower().str.strip()
    n["orig_pkts"] = _num(raw, "orig_pkts")
    n["resp_pkts"] = _num(raw, "resp_pkts")
    if "local_orig" in raw.columns:
        n["local_orig"] = raw["local_orig"].map(_to_bool).astype("object")
    return n


def normalize_binetflow(df: pd.DataFrame) -> pd.DataFrame:
    """Map a loaded CTU-13 binetflow frame to NORMALIZED_COLUMNS (training source).

    Uses the directional packet counts ``SrcPkts``/``DstPkts`` present in the
    ``.binetflow.2format`` schema; ``Dport_n`` is the audit loader's numeric port
    (falls back to raw ``Dport``). No ``local_orig`` and no ``Label`` are carried.
    """
    n = pd.DataFrame(index=df.index)
    n["ts"] = ensure_datetime(df["ts"])
    n["orig_h"] = df["SrcAddr"].astype(str)
    n["resp_h"] = df["DstAddr"].astype(str)
    n["resp_p"] = _num(df, "Dport_n") if "Dport_n" in df.columns else _num(df, "Dport")
    n["proto"] = df["Proto"].astype(str).str.lower().str.strip()
    n["orig_pkts"] = _num(df, "SrcPkts")
    n["resp_pkts"] = _num(df, "DstPkts")
    return n
