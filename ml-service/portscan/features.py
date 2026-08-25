#!/usr/bin/env python3
"""Windowing and behavioural feature computation for port-scan detection.

This is the SINGLE implementation of the feature contract.  Training extraction
and live inference both import from here, so a feature can never drift between
the two paths -- that drift is the classic way a detector that scores well
offline fails in the field.

Relationship to ``src/extract_features_v3.py``
----------------------------------------------
That module is retained unmodified as the historical v3 implementation and as the
provenance of the existing v3 CSVs.  This module is its successor.  The windowing
grid is deliberately reproduced flow-for-flow so that v4 tables differ from v3
tables in exactly one respect: the treatment of Zeek's ``RSTO`` connection state.

The RSTO change
---------------
v3 used ``FAILED_STATES = {"S0", "REJ", "RSTO"}``.  ``RSTO`` means the originator
completed the TCP handshake and then reset the connection, so the connection
*succeeded*; counting it as a failure is wrong on the merits.  nmap resets every
connection it opens, so ``-sT`` connect scans of OPEN ports were being recorded
as failures, and ``failed_conn_ratio`` partly encoded "nmap produced this flow"
rather than "this source is scanning".

Measured on the 68 laboratory captures before making the change:

===========  =============  =======  ======  =======  ==================
role         flows          REJ      S0      RSTO     in FAILED_STATES
===========  =============  =======  ======  =======  ==================
scanner            169,166   95.48%   2.78%   1.74%            100.00%
benign              19,695   27.34%   5.57%   0.00%             32.91%
===========  =============  =======  ======  =======  ==================

Two things follow, and both matter for how much this change is worth.

It is a genuine correctness fix for connect-scan windows: captures whose flows are
predominantly RSTO move from ``failed_conn_ratio`` 1.000 to 0.231.

It is NOT sufficient to desaturate the feature overall.  RSTO is only 1.74% of
scanner flows, and not one of the 169,166 scanner flows is ``SF``.  Wide scans
sweep thousands of ports of which almost none are open, so they legitimately fail
close to 100% of the time.  That is real scan behaviour rather than a tool
artifact, and the remedy is a laboratory whose targets expose enough listening
ports for a sweep to partially succeed -- not a feature edit.

What the change actually bought, measured on the 1,470-window lab corpus:
``failed_conn_ratio`` took **exactly one distinct value** across all 438 scan
windows under v3 -- a constant 1.000 -- against 61 distinct values under v4, with
only 84 windows still at 1.000.  Its single-feature AUC fell from 0.878 to 0.698.
A feature becoming *less* predictive on its own is the desired direction here: the
predictive part that disappeared was the tool artifact.

And where the artifact went
---------------------------
Splitting RSTO into its own column relocated the shortcut rather than removing it.
``rsto_ratio`` is nonzero in 354 of 438 lab scan windows and in **0 of 1,032**
benign windows, across all eight benign profiles -- a perfect one-sided indicator
with no benign variance whatsoever.  It is therefore held out of the fitted set;
see ``DIAGNOSTIC_COLUMNS``.

Feature-set note
----------------
``failed_conn_ratio`` is exactly ``s0_ratio + rej_ratio``, so it is perfectly
collinear with two other fitted features.  This is inherited from v3, where it was
collinear with ``s0_ratio + rej_ratio`` plus the RSTO share.  It is kept because it
names the behavioural quantity of interest ("no connection was established") and
because dropping it would silently change the meaning of every prior result.
Linear-model coefficients on these three must therefore not be read individually.

Feature discipline
------------------
Every feature here is computable from passive Zeek/TShark connection metadata that
the SIH real-time pipeline will actually receive.  No feature reads an address, a
raw port number, a timestamp, a capture identifier, a label, or a raw history
string.  ``syn_only_ratio`` inspects history only to test one boolean per flow and
emits an aggregate.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable, Iterator, Sequence

# --------------------------------------------------------------------- contract

WINDOW_SECONDS = 30.0
STRIDE_SECONDS = 10.0
MIN_FLOWS = 5

# A connection that never established.  RSTO is deliberately absent: see the
# module docstring.  Persisted into the model artifact so inference can refuse to
# run against a definition it was not trained under.
FAILED_STATES = frozenset({"S0", "REJ"})

# Connection states that indicate the handshake completed.  Reported for
# diagnostics; a scanner that finds an open port shows up here.
ESTABLISHED_STATES = frozenset({"SF", "RSTO", "RSTR", "S1", "S2", "S3"})

FEATURE_COLUMNS: tuple[str, ...] = (
    "unique_dst_ports", "unique_dst_hosts", "max_ports_to_single_host",
    "max_hosts_on_single_port", "ports_per_host", "dst_port_entropy",
    "fanout_ratio", "connection_attempts", "connections_per_sec",
    "failed_conn_ratio", "s0_ratio", "rej_ratio", "resp_ratio",
    "zero_resp_ratio", "avg_pkts_per_conn", "avg_duration", "iat_cv",
    "syn_only_ratio",
)

# Computed and written to every feature table, but NOT fitted.  These are held
# back because the laboratory cannot currently estimate their benign distribution,
# so a coefficient fitted on one would be fitted against no benign variation at
# all.  Promotable to FEATURE_COLUMNS once the corpus supports them -- the column
# is in the CSVs precisely so that can be checked without re-extracting.
#
# `rsto_ratio`: nonzero in 354 of 438 laboratory scan windows and in 0 of 1,032
# benign windows, across all eight benign profiles.  A perfect one-sided
# indicator with zero benign variance.  The cause is the laboratory, not the
# world: the benign profiles use curl and nc, which close connections gracefully,
# while real clients abort transfers, time out and get reset by load balancers.
# Fitting it would put "the client sent RST" in the model as a scan signal on the
# strength of a corpus where only the scanner ever did -- the same shape of
# shortcut that gave the pilot sub-1% precision on real traffic.  This decision
# rests on the training corpus alone; no held-out dataset was consulted.  The fix
# is a benign profile that resets connections, which belongs with the other
# corpus work.
DIAGNOSTIC_COLUMNS: tuple[str, ...] = ("rsto_ratio",)

# What a feature table carries, in order.  Diagnostics sit after the features so
# that a reader can see at a glance that they are outside the fitted set.
TABLE_FEATURE_COLUMNS: tuple[str, ...] = FEATURE_COLUMNS + DIAGNOSTIC_COLUMNS

# Raw counts carried in the alert's ``evidence`` block for a human analyst.  These
# must NEVER enter the feature vector: they are unnormalised magnitudes, so a
# model fitted on them would key on the traffic volume of whichever network it was
# trained in.  ``assert_feature_discipline`` enforces the separation.
EVIDENCE_ONLY_COLUMNS: tuple[str, ...] = ("failed_connections", "scan_rate")

# Columns that identify or label a window.  Never features.
IDENTIFIER_COLUMNS: tuple[str, ...] = (
    "capture", "src_ip", "window_start_ts", "window_end_ts",
    "evaluation_role", "port_scan",
)


@dataclass(frozen=True, slots=True)
class WindowSpec:
    """Windowing parameters, carried into the model artifact.

    Held as an object rather than read from module globals so that inference can
    reconstruct the exact geometry a model was trained under, and fail loudly if
    it differs.
    """

    window_seconds: float = WINDOW_SECONDS
    stride_seconds: float = STRIDE_SECONDS
    min_flows: int = MIN_FLOWS

    def as_dict(self) -> dict[str, float | int]:
        return {
            "window_seconds": self.window_seconds,
            "stride_seconds": self.stride_seconds,
            "min_flows": self.min_flows,
        }


@dataclass(frozen=True, slots=True)
class Flow:
    """One connection record, normalised away from any particular source format.

    This is the boundary that lets the same feature code serve a Zeek TSV file, a
    Zeek JSON stream, a PCAP replay and a TShark pipe.  Adapters in
    ``portscan.sources`` are responsible for parsing and type coercion; everything
    downstream sees only this.

    ``dst_port`` is kept as ``str`` because it is used solely as an opaque grouping
    key for cardinality and entropy counts.  Keeping it non-numeric makes it
    structurally impossible for a port number to be fed to a model as a magnitude.
    """

    ts: float
    src_ip: str
    dst_ip: str
    dst_port: str
    conn_state: str
    duration: float
    orig_pkts: float
    resp_pkts: float
    history: str


@dataclass(frozen=True, slots=True)
class Window:
    """A scored-or-scorable window: identity, computed metrics, analyst evidence.

    ``features`` holds every computed window aggregate, fitted or not.
    ``FEATURE_COLUMNS`` is the allowlist that decides which of them a model
    actually sees; ``DIAGNOSTIC_COLUMNS`` names the rest.  Keeping one dict and one
    allowlist -- rather than two dicts -- means a column can be promoted or demoted
    by editing the allowlist alone, and the guard has a single place to check.
    """

    src_ip: str
    start_ts: float
    end_ts: float
    features: dict[str, float]
    evidence: dict[str, float]

    def feature_vector(self, columns: Sequence[str] = FEATURE_COLUMNS) -> list[float]:
        """Fitted features, in a fixed, explicit order.

        Inference must never rely on dict ordering to line up with a fitted
        model's columns, so the order is always passed in from the artifact.
        """
        return [self.features[name] for name in columns]


def assert_feature_discipline() -> None:
    """Fail at import time if the feature/evidence/identifier split is violated.

    A cheap guard against the most damaging possible regression: an identifier, a
    raw count, or a held-back diagnostic silently becoming a model input.
    """
    features = set(FEATURE_COLUMNS)
    overlaps = {
        "feature/evidence-only": features & set(EVIDENCE_ONLY_COLUMNS),
        "feature/identifier": features & set(IDENTIFIER_COLUMNS),
        "feature/diagnostic": features & set(DIAGNOSTIC_COLUMNS),
    }
    for label, shared in overlaps.items():
        if shared:
            raise AssertionError(f"{label} overlap: {sorted(shared)}")
    if len(features) != len(FEATURE_COLUMNS):
        raise AssertionError("duplicate names in FEATURE_COLUMNS")
    if "RSTO" in FAILED_STATES:
        raise AssertionError(
            "RSTO is back in FAILED_STATES; a completed handshake is not a failure"
        )


assert_feature_discipline()


# ------------------------------------------------------------------- primitives

def entropy(counter: Counter[str], total: int) -> float:
    """Shannon entropy in bits over destination-port shares."""
    return -sum((count / total) * math.log2(count / total) for count in counter.values())


def iat_coefficient_of_variation(timestamps: Sequence[float]) -> float:
    """Dispersion of inter-arrival times, normalised by their mean.

    Scale-free by construction, which is the point: it separates the metronomic
    pacing of a scanner from bursty human traffic without depending on the
    absolute rate, so it has a chance of transferring between networks.
    """
    ordered = sorted(timestamps)
    intervals = [right - left for left, right in zip(ordered, ordered[1:])]
    if not intervals:
        return 0.0
    mean = sum(intervals) / len(intervals)
    if mean == 0:
        return 0.0
    variance = sum((item - mean) ** 2 for item in intervals) / len(intervals)
    return math.sqrt(variance) / mean


# --------------------------------------------------------- feature computation

def compute_window(
    flows: Sequence[Flow],
    start_ts: float,
    end_ts: float,
    spec: WindowSpec = WindowSpec(),
) -> Window | None:
    """Aggregate one window's flows into features plus analyst evidence.

    Returns ``None`` when the window holds fewer than ``spec.min_flows`` flows.
    That is a deliberate abstention rather than a negative prediction: with four
    connections there is no behavioural evidence either way, and emitting a
    confident "benign" would be a fabrication. Callers must propagate the
    abstention rather than coerce it to 0.

    This function is the only place window features are computed, for training and
    for inference alike.
    """
    count = len(flows)
    if count < spec.min_flows:
        return None

    dst_ports = Counter(flow.dst_port for flow in flows)
    dst_hosts = Counter(flow.dst_ip for flow in flows)
    ports_by_host: dict[str, set[str]] = defaultdict(set)
    hosts_by_port: dict[str, set[str]] = defaultdict(set)
    for flow in flows:
        ports_by_host[flow.dst_ip].add(flow.dst_port)
        hosts_by_port[flow.dst_port].add(flow.dst_ip)

    states = [flow.conn_state for flow in flows]
    orig_packets = [flow.orig_pkts for flow in flows]
    resp_packets = [flow.resp_pkts for flow in flows]
    total_orig, total_resp = sum(orig_packets), sum(resp_packets)
    unique_hosts, unique_ports = len(dst_hosts), len(dst_ports)

    failed_connections = sum(state in FAILED_STATES for state in states)
    timestamps = [flow.ts for flow in flows]

    # Observed span, not the nominal window length.  A window can hold flows
    # spanning a fraction of its width, and an analyst reading `scan_rate` wants
    # the rate at which connections actually arrived.  `connections_per_sec` keeps
    # the fixed denominator so that it stays comparable across windows and remains
    # a valid model input.
    span = max(timestamps) - min(timestamps)
    scan_rate = count / span if span > 0 else count / spec.window_seconds

    # Count-valued features stay `int`, matching v3, so a v4 CSV is textually
    # comparable with a v3 one instead of differing by a trailing ".0" in every
    # count column.  Both are acceptable model inputs.
    features = {
        "unique_dst_ports": unique_ports,
        "unique_dst_hosts": unique_hosts,
        "max_ports_to_single_host": max(map(len, ports_by_host.values())),
        "max_hosts_on_single_port": max(map(len, hosts_by_port.values())),
        "ports_per_host": round(unique_ports / unique_hosts, 6),
        "dst_port_entropy": round(entropy(dst_ports, count), 6),
        "fanout_ratio": round(unique_ports / count, 6),
        "connection_attempts": count,
        "connections_per_sec": round(count / spec.window_seconds, 6),
        "failed_conn_ratio": round(failed_connections / count, 6),
        "s0_ratio": round(states.count("S0") / count, 6),
        "rej_ratio": round(states.count("REJ") / count, 6),
        "rsto_ratio": round(states.count("RSTO") / count, 6),
        "resp_ratio": round(total_resp / total_orig, 6) if total_orig else 0.0,
        "zero_resp_ratio": round(sum(value == 0 for value in resp_packets) / count, 6),
        "avg_pkts_per_conn": round((total_orig + total_resp) / count, 6),
        "avg_duration": round(sum(flow.duration for flow in flows) / count, 6),
        "iat_cv": round(iat_coefficient_of_variation(timestamps), 6),
        "syn_only_ratio": round(sum(flow.history == "S" for flow in flows) / count, 6),
    }

    evidence = {
        # Duplicated from the features on purpose: these are the numbers an
        # analyst needs in the alert, and the alert must not require the reader to
        # go and recompute them.
        "unique_dst_hosts": unique_hosts,
        "unique_dst_ports": unique_ports,
        "connection_attempts": count,
        # Evidence-only, never a feature.
        "failed_connections": failed_connections,
        "scan_rate": round(scan_rate, 4),
    }

    return Window(
        src_ip=flows[0].src_ip,
        start_ts=round(start_ts, 6),
        end_ts=round(end_ts, 6),
        features=features,
        evidence=evidence,
    )


# -------------------------------------------------------------- batch windowing

def window_offsets(spec: WindowSpec) -> range:
    return range(math.ceil(spec.window_seconds / spec.stride_seconds))


def candidate_window_indices(timestamps: Iterable[float], spec: WindowSpec) -> list[int]:
    """Grid indices of every window that could contain at least one flow.

    Walking the grid from a capture's first timestamp to its last is impractical
    for CTU's multi-week malware capture -- it would inspect millions of empty
    windows -- so only windows anchored near an actual flow are considered. This
    reproduces the v3 behaviour exactly; changing it would shift window boundaries
    and make v3/v4 tables incomparable.
    """
    offsets = window_offsets(spec)
    return sorted({
        math.floor(timestamp / spec.stride_seconds) - offset
        for timestamp in timestamps
        for offset in offsets
    })


def windows_for_source(
    flows: Sequence[Flow],
    spec: WindowSpec = WindowSpec(),
) -> Iterator[Window]:
    """Slide the window grid over one source's flows, in time order.

    Windows are computed per source IP and never across sources. That is what
    makes a per-source capture equivalent to a merged one, and it is why the
    laboratory can capture each container separately.
    """
    timed = sorted(flows, key=lambda flow: flow.ts)
    timestamps = [flow.ts for flow in timed]

    left = right = 0
    for index in candidate_window_indices(timestamps, spec):
        start = index * spec.stride_seconds
        end = start + spec.window_seconds
        while left < len(timed) and timed[left].ts < start:
            left += 1
        right = max(right, left)
        while right < len(timed) and timed[right].ts < end:
            right += 1
        window = compute_window(timed[left:right], start, end, spec)
        if window is not None:
            yield window


def windows_from_flows(
    flows: Iterable[Flow],
    spec: WindowSpec = WindowSpec(),
) -> Iterator[Window]:
    """Batch windowing over a mixed stream of sources.

    Groups by source first, so this holds every flow in memory and is for offline
    extraction only. Live inference uses ``portscan.streaming``, which bounds its
    buffers, and shares ``compute_window`` with this path.
    """
    by_source: dict[str, list[Flow]] = defaultdict(list)
    for flow in flows:
        by_source[flow.src_ip].append(flow)
    for src_ip in sorted(by_source):
        yield from windows_for_source(by_source[src_ip], spec)
