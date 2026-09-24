"""
C2 Beaconing Detector.

Detects command-and-control beaconing: a host repeatedly connecting to the
same destination at REGULAR time intervals (periodicity). This is the
signature of malware phoning home to its C2 server.

Distinct from EncryptedMalware (which analyzes a single flow's characteristics),
this detector analyzes the TEMPORAL PATTERN across many connections between
the same (src_ip -> dst_ip:dst_port) pair over time.

Constraints:
  a. Read-only ingest — passive, no return path
  b. No payload decryption — connection metadata only
  c. Streaming — maintains rolling connection-time history per endpoint pair
  d. Bounded memory — history capped per pair, stale pairs evicted
  e. Standardized alerts — timestamp, flow id, confidence, evidence
"""

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class BeaconTracker:
    """Tracks connection timestamps for one (src, dst, dport) endpoint pair."""
    # Cap high enough to hold a slow beacon's history across a long span
    # (e.g. a 60s beacon over ~30 min = 30 check-ins) without truncating.
    connect_times: deque = field(default_factory=lambda: deque(maxlen=256))
    total_bytes: int = 0
    total_conns: int = 0
    last_seen: float = 0.0


class C2BeaconDetector:
    """
    Detects periodic beaconing by analyzing inter-connection intervals
    between the same source and destination endpoint over time.
    """

    # Tuning parameters
    #
    # These are tuned for REAL live C2 traffic, not just a fast scripted demo.
    # Live beacons check in on human/operator-scale cadences — commonly 30s, 60s,
    # a few minutes, or longer — with jitter added by the framework (often
    # 10-30%) plus OS/connect latency on top. The previous 1-15s interval /
    # 180s span envelope only matched a tight demo beacon and structurally
    # rejected every realistic beacon (its intervals fell outside the window and
    # 6 check-ins never fit in 180s). The window below covers the common range.
    #
    # The feature-extractor applies cross-detector suppression and an
    # established / data-carrying / non-standard-port / rate guard BEFORE feeding
    # events here, so this stage already sees only clean, low-rate connections —
    # widening the periodicity envelope does not open the door to floods/scans.
    MIN_BEACONS = 4           # need at least this many connections to assess periodicity
    # Coefficient of variation below this = regular beacon. Raised from 0.40 to
    # 0.50 to tolerate the jitter real frameworks inject and live connect
    # latency, while staying well below bursty/random human traffic (CV > 1.0).
    MAX_JITTER_CV = 0.50
    MIN_INTERVAL = 1.0        # ignore sub-second spacing (flood/scan bursts, not beacons)
    # Upper bound on a usable beacon interval. Widened from 15s to 900s (15 min)
    # so ordinary 30s / 60s / few-minute beacons are actually measured instead of
    # being filtered out. Sparse unrelated connections are still rejected by the
    # jitter (CV) and minimum-beacon-count checks below.
    MAX_INTERVAL = 900.0
    MIN_MEAN_INTERVAL = 1.0   # a true beacon phones home every second+, not bursts
    MIN_TOTAL_BYTES = 200     # reject near-empty periodic noise
    MIN_BEACONS_STRICT = 5    # require a few more events than the bare minimum
    # All beacons must fall within this span. Widened from 180s to 3600s (1 hr)
    # so a slow 60s+ beacon can accumulate enough check-ins to be assessed. The
    # per-pair history (BeaconTracker) and PAIR_TTL below are sized to match.
    MAX_TOTAL_SPAN = 3600.0
    PAIR_TTL = 1800.0         # evict endpoint pairs idle for 30 min. Long enough
    #                           to retain a slow live beacon's history between
    #                           check-ins, short enough to drop stale endpoints.

    def __init__(self):
        self.trackers: Dict[Tuple[str, str, int], BeaconTracker] = {}
        self.model_name = "c2_beacon_periodicity"
        self.threshold = 0.7
        logger.info("Loaded C2 Beacon detector (periodicity analysis, hardened)")
        logger.info(f"  Min beacons: {self.MIN_BEACONS_STRICT}, Max jitter CV: "
                    f"{self.MAX_JITTER_CV}, Max interval: {self.MAX_INTERVAL}s, "
                    f"Max span: {self.MAX_TOTAL_SPAN}s")

    def observe(self, src_ip: str, dst_ip: str, dst_port: int, ts: float, nbytes: int):
        """Record a connection event between src and dst."""
        key = (src_ip, dst_ip, dst_port)
        tr = self.trackers.get(key)
        if tr is None:
            tr = BeaconTracker()
            self.trackers[key] = tr
        tr.connect_times.append(ts)
        tr.total_bytes += nbytes
        tr.total_conns += 1
        tr.last_seen = ts

    def _score_pair(self, tr: BeaconTracker) -> Optional[dict]:
        """
        Compute a beaconing score from the connection-time history.
        Returns evidence dict if it looks like beaconing, else None.
        """
        times = sorted(tr.connect_times)
        if len(times) < self.MIN_BEACONS_STRICT:
            return None

        # Require the beacons to be temporally clustered. A real beacon fires a
        # steady stream within a bounded span; unrelated sparse connections spread
        # over a long period are NOT a beacon even if the average looks regular.
        total_span = times[-1] - times[0]
        if total_span > self.MAX_TOTAL_SPAN:
            return None

        # Compute inter-connection intervals
        intervals = np.diff(times)
        # Keep only plausible beacon intervals
        intervals = intervals[(intervals >= self.MIN_INTERVAL) & (intervals <= self.MAX_INTERVAL)]
        if len(intervals) < self.MIN_BEACONS_STRICT - 1:
            return None

        mean_iv = float(np.mean(intervals))
        std_iv = float(np.std(intervals))
        if mean_iv <= 0:
            return None

        # Reject burst-spaced connections (floods/scans hammer sub-second); a
        # genuine beacon phones home on a human-scale cadence.
        if mean_iv < self.MIN_MEAN_INTERVAL:
            return None

        # Reject near-empty periodic noise — beacons carry a real (if small) payload.
        if tr.total_bytes < self.MIN_TOTAL_BYTES:
            return None

        # Coefficient of variation — low = very regular = beaconing
        cv = std_iv / mean_iv

        if cv > self.MAX_JITTER_CV:
            return None  # too irregular to be a beacon

        # Confidence: lower jitter + more beacons = higher confidence
        regularity = 1.0 - min(cv / self.MAX_JITTER_CV, 1.0)
        volume_factor = min(len(intervals) / 20.0, 1.0)
        confidence = 0.70 + 0.29 * (0.6 * regularity + 0.4 * volume_factor)
        confidence = min(confidence, 0.99)

        return {
            "beacon_count": len(times),
            "mean_interval_sec": round(mean_iv, 2),
            "jitter_cv": round(cv, 3),
            "interval_std_sec": round(std_iv, 2),
            "total_bytes": tr.total_bytes,
            "confidence": confidence,
        }

    def scan(self):
        """
        Scan all tracked endpoint pairs for beaconing patterns.
        Returns list of (src_ip, dst_ip, dst_port, evidence) for detections.
        Also evicts stale trackers.
        """
        now = time.time()
        detections = []
        stale = []

        # DEBUG: report tracker state
        if self.trackers:
            summary = {str(k): len(v.connect_times) for k, v in list(self.trackers.items())[:5]}
            logger.info(f"C2 DEBUG scan: {len(self.trackers)} trackers, sample={summary}")

        for key, tr in self.trackers.items():
            # Evict stale pairs
            if now - tr.last_seen > self.PAIR_TTL:
                stale.append(key)
                continue

            ev = self._score_pair(tr)
            if ev is not None:
                src_ip, dst_ip, dst_port = key
                detections.append((src_ip, dst_ip, dst_port, ev))
            elif len(tr.connect_times) >= 2:
                # DEBUG: explain why a multi-event pair didn't score
                t = sorted(tr.connect_times)
                span = t[-1] - t[0]
                ivs = np.diff(t)
                ivs_f = ivs[(ivs >= self.MIN_INTERVAL) & (ivs <= self.MAX_INTERVAL)]
                m = float(np.mean(ivs_f)) if len(ivs_f) else 0.0
                cv = (float(np.std(ivs_f)) / m) if m > 0 else -1
                logger.info(
                    f"C2 DEBUG pair {key}: events={len(t)} span={span:.1f}s "
                    f"usable_ivs={len(ivs_f)} mean_iv={m:.2f} cv={cv:.3f} "
                    f"bytes={tr.total_bytes} "
                    f"(need events>={self.MIN_BEACONS_STRICT} span<={self.MAX_TOTAL_SPAN} "
                    f"cv<={self.MAX_JITTER_CV})"
                )

        for key in stale:
            self.trackers.pop(key, None)

        return detections

    def is_beacon(self, confidence: float) -> bool:
        return confidence >= self.threshold

    def severity(self, confidence: float) -> str:
        if confidence >= 0.95:
            return "CRITICAL"
        elif confidence >= 0.85:
            return "HIGH"
        elif confidence >= 0.75:
            return "MEDIUM"
        else:
            return "LOW"
