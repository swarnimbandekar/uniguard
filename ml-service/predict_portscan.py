#!/usr/bin/env python3
"""Predict path: passive flow metadata in, standardized port-scan alerts out.

This is the ``predict`` half of the component and the thing the SIH pipeline
actually runs.  It loads the persisted artifact, opens a flow source, windows the
stream incrementally in bounded memory, scores each window with the calibrated
model, and emits a standardized alert for every window that clears the artifact's
frozen threshold.  It shares the feature contract, window geometry, and alert
schema with the train path through the ``portscan`` package, so what it scores in
the field is byte-identical to what the model was fitted on.

The whole path is passive.  Every source adapter reads logs, files, or a capture
handle; none emits a packet.  Scan *generation* lives elsewhere, in an isolated
Docker bridge, and nothing reachable from here can touch it.

Sources (``--source``)
----------------------
::

    zeek:<path>          read a Zeek conn.log once, then stop (offline / PCAP eval)
    zeek-tail:<path>     tail a live Zeek conn.log (the deployed path)
    pcap:<path>          run Zeek over a PCAP, then stream its flows (needs --work-dir)
    tshark:<path.pcap>   approximate flows from a PCAP via TShark
    iface:<name>         approximate flows from a live interface via TShark

A bare path is ``pcap:`` for ``.pcap``/``.pcapng`` and ``zeek:`` otherwise.

Output
------
Alerts are written as JSON Lines -- one alert object per line, the shape
``portscan.alert`` defines -- to stdout by default or to ``--alerts-out``.  A
human-readable run summary goes to stderr, and a machine-readable one (counts,
stream health, and inference latency) to ``--summary-out``.  Keeping alerts on
stdout alone means ``predict ... | consumer`` is a valid tail-and-forward hookup.

Inference latency
-----------------
The metric the work order calls for is the wall-clock cost of turning one window
into a score -- not detection latency.  It is reported two ways: the mean per
window as windows are scored in the stream, and, measured in isolation on a sample
of real windows, the single-window ``score`` cost as p50/p95/p99/max.  The second
is the honest live number, because a live tail usually releases one window at a
time rather than in a batch.

Usage (from the repository root)::

    .venv\\Scripts\\python.exe src\\predict_portscan.py --source zeek:data/self-generated/lab2/zeek/r6_scan_a/conn.log
    .venv\\Scripts\\python.exe src\\predict_portscan.py --source zeek-tail:/opt/zeek/logs/current/conn.log
    .venv\\Scripts\\python.exe src\\predict_portscan.py --source data/x.pcap --work-dir /tmp/zk --alerts-out alerts.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from contextlib import nullcontext
from pathlib import Path
from time import perf_counter_ns

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from portscan.alert import build_alert  # noqa: E402
from portscan.model import ArtifactMismatch, PortScanDetector  # noqa: E402
from portscan.sources import SourceStats, open_source  # noqa: E402
from portscan.streaming import (DEFAULT_LATENESS_SECONDS, StreamingWindower,  # noqa: E402
                                StreamStats)

DEFAULT_ARTIFACT = ROOT / "models" / "portscan.joblib"
DEFAULT_SUMMARY = ROOT / "results" / "predict-portscan.json"

# How many scored windows to retain for the isolated single-window latency
# benchmark.  Bounded so a live tail does not accumulate windows without limit;
# the sample is the first N, which is representative for a stationary source.
DEFAULT_LATENCY_SAMPLE = 2_000


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True,
                        help="source spec, e.g. zeek:PATH, zeek-tail:PATH, pcap:PATH, iface:NAME")
    parser.add_argument("--model", type=Path, default=DEFAULT_ARTIFACT,
                        help=f"artifact to load (default {DEFAULT_ARTIFACT.relative_to(ROOT)})")
    parser.add_argument("--alerts-out", type=Path,
                        help="write alert JSON Lines here instead of stdout")
    parser.add_argument("--summary-out", type=Path, default=DEFAULT_SUMMARY,
                        help=f"machine-readable run summary (default {DEFAULT_SUMMARY.relative_to(ROOT)})")
    parser.add_argument("--lateness", type=float, default=DEFAULT_LATENESS_SECONDS,
                        help=f"streaming lateness allowance in seconds (default {DEFAULT_LATENESS_SECONDS:g})")
    parser.add_argument("--work-dir", type=Path,
                        help="output directory for Zeek when --source is a pcap:")
    parser.add_argument("--speed", type=float, default=0.0,
                        help="pcap: replay pacing; 0 = as fast as possible, 1 = real time")
    parser.add_argument("--from-start", action=argparse.BooleanOptionalAction, default=True,
                        help="zeek-tail: read existing lines first (default) or only new ones")
    parser.add_argument("--idle-timeout", type=float,
                        help="zeek-tail/iface: stop after this many idle seconds (default: run forever)")
    parser.add_argument("--duration", type=int,
                        help="iface: capture duration in seconds")
    parser.add_argument("--latency-sample", type=int, default=DEFAULT_LATENCY_SAMPLE,
                        help=f"windows retained for the isolated latency benchmark (default {DEFAULT_LATENCY_SAMPLE})")
    parser.add_argument("--allow-version-mismatch", action="store_true",
                        help="load an artifact fitted under a different scikit-learn (downgrade to a warning)")
    parser.add_argument("--allow-uncalibrated", action="store_true",
                        help="emit alerts from an uncalibrated model (confidence would not be a probability)")
    return parser.parse_args(argv)


def source_options(arguments: argparse.Namespace) -> dict:
    """Translate CLI flags into the per-scheme keyword arguments open_source takes.

    Only the options a given scheme accepts are forwarded; passing, say, ``speed``
    to a zeek source would raise inside the adapter.  open_source ignores absent
    keys, so this stays scheme-agnostic here.
    """
    scheme = arguments.source.partition(":")[0]
    if scheme == "pcap" or (":" not in arguments.source
                            and Path(arguments.source).suffix.lower() in {".pcap", ".pcapng"}):
        if arguments.work_dir is None:
            raise SystemExit("pcap: sources need --work-dir for Zeek's output")
        return {"work_dir": arguments.work_dir, "speed": arguments.speed}
    if scheme == "zeek-tail":
        options = {"from_start": arguments.from_start}
        if arguments.idle_timeout is not None:
            options["idle_timeout"] = arguments.idle_timeout
        return options
    if scheme == "iface":
        return {"duration_seconds": arguments.duration} if arguments.duration else {}
    return {}


def percentiles(values_ns: list[int]) -> dict[str, float]:
    """p50/p95/p99/max of per-window latency, reported in microseconds."""
    if not values_ns:
        return {}
    array = np.array(values_ns, dtype=float) / 1_000.0  # ns -> us
    return {
        "p50_us": round(float(np.percentile(array, 50)), 2),
        "p95_us": round(float(np.percentile(array, 95)), 2),
        "p99_us": round(float(np.percentile(array, 99)), 2),
        "max_us": round(float(array.max()), 2),
        "mean_us": round(float(array.mean()), 2),
    }


def benchmark_single_window(detector: PortScanDetector, sample: list) -> dict:
    """Time ``score`` one window at a time -- the realistic live per-window cost.

    A live tail releases windows a few at a time, so a batched ``predict_proba``
    understates the cost per window.  This measures the path a single released
    window actually takes.  One warm-up call absorbs lazy allocation so the first
    timed call is not an outlier.
    """
    if not sample:
        return {}
    detector.score(sample[0])
    timings = []
    for window in sample:
        start = perf_counter_ns()
        detector.score(window)
        timings.append(perf_counter_ns() - start)
    result = percentiles(timings)
    result["sampled_windows"] = len(sample)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)

    try:
        detector = PortScanDetector.load(
            arguments.model, allow_version_mismatch=arguments.allow_version_mismatch)
    except (ArtifactMismatch, FileNotFoundError) as error:
        raise SystemExit(f"Cannot load model: {error}")

    if not detector.is_calibrated and not arguments.allow_uncalibrated:
        raise SystemExit(
            f"Model calibration_method={detector.calibration_method!r} is not "
            "calibrated; its scores are not probabilities and severity would be "
            "meaningless. Re-train with calibration, or pass --allow-uncalibrated "
            "for a diagnostic run.")

    print(f"model:     {detector.model_name} "
          f"(calibration {detector.calibration_method}, threshold {detector.threshold:.4f})",
          file=sys.stderr)
    print(f"corpus:    {detector.provenance.corpus_fingerprint[:12]} "
          f"({detector.provenance.row_count:,} rows, "
          f"{detector.provenance.positive_count:,} positive)", file=sys.stderr)
    handoff = detector.provenance.notes.get("handoff_ready")
    if handoff and handoff != "yes":
        print(f"note:      artifact is NOT handoff-ready "
              f"({detector.provenance.notes.get('handoff_blocker', 'see provenance')})",
              file=sys.stderr)
    print(f"source:    {arguments.source}", file=sys.stderr)
    print(f"windowing: {detector.window_spec.as_dict()}   lateness {arguments.lateness:g}s\n",
          file=sys.stderr)

    source_stats = SourceStats()
    stream_stats = StreamStats()
    windower = StreamingWindower(spec=detector.window_spec,
                                 lateness_seconds=arguments.lateness, stats=stream_stats)
    flows = open_source(arguments.source, source_stats, **source_options(arguments))

    windows_scored = 0
    alerts_emitted = 0
    severity_counter: Counter = Counter()
    truncated_alerts = 0
    score_ns_total = 0
    sample: list = []
    interrupted = False

    alerts_target = (arguments.alerts_out.open("w", encoding="utf-8")
                     if arguments.alerts_out else nullcontext(sys.stdout))
    with alerts_target as alerts_out:
        def score_and_emit(windows: list) -> None:
            nonlocal windows_scored, alerts_emitted, score_ns_total, truncated_alerts
            if not windows:
                return
            start = perf_counter_ns()
            scores = detector.score_many(windows)
            score_ns_total += perf_counter_ns() - start
            windows_scored += len(windows)
            for window, confidence in zip(windows, scores):
                if len(sample) < arguments.latency_sample:
                    sample.append(window)
                if detector.is_alert(float(confidence)):
                    alert = build_alert(window, float(confidence),
                                        detector=detector.detector_tag())
                    alerts_out.write(alert.as_json() + "\n")
                    alerts_emitted += 1
                    severity_counter[alert.severity] += 1
                    if alert.evidence.get("truncated"):
                        truncated_alerts += 1
            alerts_out.flush()

        try:
            for flow in flows:
                score_and_emit(windower.push(flow))
        except KeyboardInterrupt:
            interrupted = True
            print("\ninterrupted; flushing buffered windows", file=sys.stderr)
        # End of stream (or interrupt): release everything still held.
        score_and_emit(windower.flush())

    latency_single = benchmark_single_window(detector, sample)
    mean_window_us = round(score_ns_total / windows_scored / 1_000.0, 2) if windows_scored else 0.0

    summary = {
        "source": arguments.source,
        "interrupted": interrupted,
        "model": {
            "name": detector.model_name,
            "calibration": detector.calibration_method,
            "threshold": round(detector.threshold, 6),
            "corpus_fingerprint": detector.provenance.corpus_fingerprint,
            "handoff_ready": detector.provenance.notes.get("handoff_ready", "unknown"),
            "sklearn": detector.provenance.sklearn_version,
        },
        "counts": {
            "flows": source_stats.flows,
            "windows_scored": windows_scored,
            "alerts_emitted": alerts_emitted,
            "alerts_truncated_evidence": truncated_alerts,
            "severity_breakdown": dict(severity_counter),
            "windows_abstained": stream_stats.windows_abstained,
            "windows_truncated": stream_stats.windows_truncated,
            "flows_late": stream_stats.flows_late,
            "flows_partly_late": stream_stats.flows_partly_late,
            "flows_refused": stream_stats.flows_refused,
            "sources_seen": stream_stats.sources_seen,
            "sources_evicted": stream_stats.sources_evicted,
        },
        "inference_latency": {
            "mean_per_window_in_stream_us": mean_window_us,
            "single_window_isolated": latency_single,
        },
        "data_quality": {"problems": dict(source_stats.problems)},
    }
    arguments.summary_out.parent.mkdir(parents=True, exist_ok=True)
    arguments.summary_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n".join([
        "",
        f"flows read            {source_stats.flows:,}",
        f"windows scored        {windows_scored:,}",
        f"alerts emitted        {alerts_emitted:,}  "
        f"({', '.join(f'{k} {v}' for k, v in severity_counter.most_common()) or 'none'})",
        *(["windows truncated     %d (evidence is a lower bound)" % stream_stats.windows_truncated]
          if stream_stats.windows_truncated else []),
        *stream_stats.report(),
        "",
        f"inference latency, per window scored in stream: {mean_window_us:g} us mean",
    ]), file=sys.stderr)
    if latency_single:
        print(f"inference latency, single window isolated ({latency_single['sampled_windows']:,} "
              f"sampled): p50 {latency_single['p50_us']:g} us, p95 {latency_single['p95_us']:g} us, "
              f"p99 {latency_single['p99_us']:g} us, max {latency_single['max_us']:g} us",
              file=sys.stderr)
    if arguments.alerts_out:
        print(f"\nalerts  -> {arguments.alerts_out}", file=sys.stderr)
    print(f"summary -> {arguments.summary_out.relative_to(ROOT) if arguments.summary_out.is_relative_to(ROOT) else arguments.summary_out}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
