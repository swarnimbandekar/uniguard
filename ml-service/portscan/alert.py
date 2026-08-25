#!/usr/bin/env python3
"""The standardized alert this component emits, and the rules for building one.

The consuming chain is Real-Time Pipeline -> Threat Fusion -> Alert Engine ->
FastAPI/WebSocket -> SOC Dashboard, so the output shape is a contract with four
other teams rather than an implementation detail.  The required shape is::

    {
      "threat_class": "PORT_SCAN",
      "confidence": 0.96,
      "severity": "HIGH",
      "evidence": {
        "unique_dst_hosts": 72, "unique_dst_ports": 341,
        "connection_attempts": 580, "failed_connections": 510, "scan_rate": 32.1
      }
    }

Those four keys and those five evidence fields are always present and always
spelled this way; ``assert_alert_contract`` fails at import if that stops being
true.  Everything this module adds beyond them -- ``source_ip``, ``window``,
``detector``, ``schema_version`` -- is additive, because an alert that says a scan
happened without saying who or when is not actionable, and Threat Fusion needs to
correlate on source and time.

Raw counts are evidence, never features
---------------------------------------
``failed_connections`` and ``scan_rate`` are RAW COUNTS, while the model is fitted
on ratios (``failed_conn_ratio``, ``connections_per_sec``).  That asymmetry is
deliberate and load-bearing.  An analyst reading an alert needs "510 of 580
connections failed"; a model fitted on 510 would key on the traffic volume of
whichever network it was trained in and would not transfer.  So the counts are
computed, carried to the analyst, and kept out of the feature vector --
``features.assert_feature_discipline`` enforces the separation from the other side,
and ``assert_alert_contract`` here checks the two modules still agree on which
fields those are.

Severity
--------
Severity is derived from confidence alone.  Two things follow from that.

It is only meaningful if ``confidence`` is a CALIBRATED probability.  A raw
``predict_proba`` from a tree ensemble is not one -- it is a leaf-vote fraction
that saturates near 0 and 1 -- so severity bands over an uncalibrated score would
report CRITICAL for almost every alert.  The artifact therefore carries its
calibration method, and ``portscan.model`` refuses to build alerts from an
uncalibrated model.

Breadth is deliberately NOT part of the mapping, even though a 341-port sweep
across 72 hosts is plainly worse than five ports on one host.  Any weighting of
breadth against confidence would be a heuristic nobody has validated, and the
component's job is to report what it measured.  The breadth numbers are in
``evidence`` precisely so Threat Fusion -- which sees other detectors' output and
asset criticality, neither of which this component knows about -- can escalate on
them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .features import EVIDENCE_ONLY_COLUMNS, Window

THREAT_CLASS = "PORT_SCAN"

# Bumped when a consumer would have to change to read the output.  Additive fields
# do not bump it; renaming or removing one does.
ALERT_SCHEMA_VERSION = "1.0"

# Exactly the evidence fields the interface specifies, in the specified order.
REQUIRED_EVIDENCE_FIELDS: tuple[str, ...] = (
    "unique_dst_hosts", "unique_dst_ports", "connection_attempts",
    "failed_connections", "scan_rate",
)

# Descending, first match wins.  Bands over a calibrated probability: the top band
# is where the model is essentially certain, and LOW is everything from the
# operating threshold up to 0.80 -- an alert worth queueing, not worth waking
# someone for.  Tunable without a code change through `severity_bands`.
SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (0.98, "CRITICAL"),
    (0.90, "HIGH"),
    (0.80, "MEDIUM"),
    (0.00, "LOW"),
)

SEVERITIES: tuple[str, ...] = tuple(name for _, name in SEVERITY_BANDS)


def assert_alert_contract() -> None:
    """Fail at import if the alert contract has drifted.

    Three ways this project could break its promise to the consuming teams, all
    cheap to rule out and expensive to discover downstream: the evidence fields
    could be renamed, the raw-count fields could stop matching what
    ``features`` holds out of the feature vector, or the severity bands could stop
    covering the probability range.
    """
    missing = set(EVIDENCE_ONLY_COLUMNS) - set(REQUIRED_EVIDENCE_FIELDS)
    if missing:
        raise AssertionError(
            f"features declares {sorted(missing)} evidence-only, but the alert "
            "schema has nowhere to put them"
        )
    if not SEVERITY_BANDS or SEVERITY_BANDS[-1][0] > 0.0:
        raise AssertionError("severity bands must cover down to 0.0")
    floors = [floor for floor, _ in SEVERITY_BANDS]
    if floors != sorted(floors, reverse=True):
        raise AssertionError("severity bands must be listed in descending order")


assert_alert_contract()


def severity_for(
    confidence: float,
    bands: tuple[tuple[float, str], ...] = SEVERITY_BANDS,
) -> str:
    for floor, name in bands:
        if confidence >= floor:
            return name
    # Unreachable while the contract assertion holds; kept so a caller passing
    # custom bands gets a clear failure rather than a silent None.
    raise ValueError(f"no severity band matches confidence {confidence!r}")


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class Alert:
    """One emitted detection, serialisable to the standardized shape."""

    threat_class: str
    confidence: float
    severity: str
    evidence: dict[str, float]
    source_ip: str
    window_start_ts: float
    window_end_ts: float
    detector: dict[str, str] = field(default_factory=dict)
    schema_version: str = ALERT_SCHEMA_VERSION

    def as_dict(self) -> dict:
        """The required keys first, in the specified order, then the additions."""
        return {
            "threat_class": self.threat_class,
            "confidence": self.confidence,
            "severity": self.severity,
            "evidence": dict(self.evidence),
            "source_ip": self.source_ip,
            "window": {
                "start_ts": self.window_start_ts,
                "end_ts": self.window_end_ts,
                "start": _iso(self.window_start_ts),
                "end": _iso(self.window_end_ts),
                "seconds": round(self.window_end_ts - self.window_start_ts, 6),
            },
            "detector": dict(self.detector),
            "schema_version": self.schema_version,
        }

    def as_json(self) -> str:
        """One line of JSON, which is what a tail-and-forward consumer wants."""
        return json.dumps(self.as_dict(), separators=(",", ":"))


def build_evidence(window: Window) -> dict[str, float]:
    """The evidence block for one window, in the specified field order.

    Reads ``Window.evidence``, which ``features.compute_window`` populates, rather
    than recomputing anything: a second computation of ``failed_connections`` here
    could disagree with the one the features were derived from.
    """
    missing = [name for name in REQUIRED_EVIDENCE_FIELDS if name not in window.evidence]
    if missing:
        raise ValueError(f"window evidence is missing required fields: {missing}")
    evidence = {name: window.evidence[name] for name in REQUIRED_EVIDENCE_FIELDS}
    # Streaming sets this when a buffer cap forced flows to be refused, making the
    # volume numbers lower bounds.  Carried through so a consumer is not misled by
    # a count that looks exact.
    if window.evidence.get("truncated"):
        evidence["truncated"] = True
    return evidence


def build_alert(
    window: Window,
    confidence: float,
    detector: dict[str, str] | None = None,
    bands: tuple[tuple[float, str], ...] = SEVERITY_BANDS,
) -> Alert:
    """Assemble one alert. Thresholding is the caller's decision, not this one's.

    Deciding whether a score clears the operating threshold belongs with the model
    and its persisted threshold, so this builds an alert for a score that has
    already been judged alertable.  ``portscan.model.PortScanDetector`` is the
    caller that owns that judgement.
    """
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"confidence must be a probability, got {confidence!r}")
    return Alert(
        threat_class=THREAT_CLASS,
        # Four places: enough to distinguish severity bands and to be read by a
        # human, without implying a precision the calibration does not have.
        confidence=round(float(confidence), 4),
        severity=severity_for(confidence, bands),
        evidence=build_evidence(window),
        source_ip=window.src_ip,
        window_start_ts=window.start_ts,
        window_end_ts=window.end_ts,
        detector=dict(detector or {}),
    )
