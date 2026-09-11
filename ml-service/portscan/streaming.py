#!/usr/bin/env python3
"""Incremental, bounded-memory windowing for live inference.

``portscan.features.windows_from_flows`` groups an entire capture by source before
windowing anything.  That is correct for offline extraction and impossible live: it
holds every flow ever seen.  This module produces the same windows from a stream,
with buffers that do not grow without limit, and it does so by calling the very
same ``features.compute_window`` -- there is no second feature implementation
here, only a different way of deciding which flows go into a window and when.

``src/verify_streaming_parity.py`` checks the "same windows" claim capture by
capture rather than asserting it.

Why flows arrive out of order
-----------------------------
Zeek writes a ``conn.log`` line when a connection *ends*, but stamps it with the
time the connection *started*.  A tail therefore receives records in end-time
order carrying start-time timestamps, so a long-lived connection surfaces long
after windows covering its start have passed.  Measured over the corpus, worst
per-source lag between a flow's timestamp and the highest timestamp already seen:

===========================================  =========  ============
capture                                          flows      max lag
===========================================  =========  ============
laboratory (68 captures, worst case)             38,912        5.00 s
ctu-idseval-6-malicious-portscan-3              131,150      104.37 s
ctu-idseval-6-malicious-malware-2               185,506      392.52 s
ctu-idseval-6-benign-user-traffic-1              35,046   24,687.76 s
ctu-idseval-6-malicious-malware-1                90,060   82,186.97 s
===========================================  =========  ============

82,187 s is 22.8 hours -- one idle TCP session held open across a day and logged
at close.  No streaming detector can buffer 22.8 hours of flows to place that
record in its rightful window, so lateness is a bounded allowance and anything
beyond it is dropped and **counted**, never quietly folded into the wrong window.

The loss is graded rather than a cliff, because a flow belongs to ``span``
consecutive windows.  A flow lagging the watermark by less than
``lateness + stride`` reaches all of them; past that it starts missing its
earliest windows (``StreamStats.flows_partly_late``); it is lost outright only
once its start precedes the oldest window still open (``flows_late``).
``verify_streaming_parity.py`` reports the resulting window differences per
capture instead of leaving them to be assumed negligible.

That this is survivable for *this* detector is a property of what a scan looks
like, not a general result: scan flows are short and dense, so they arrive
promptly.  The flows that arrive hours late are long-lived sessions, and each one
contributes a single connection to a window.  It would not be survivable for a
detector keyed on long-session behaviour.

Bounded memory
--------------
Two caps, both counted when they bite:

``max_flows_per_source``
    Retention is at most ``window + lateness`` seconds per source, so this only
    engages against a flood.  It is a safety valve, not routine: the widest
    laboratory scan window holds 14,556 connections, well inside the default.
    When it engages the newest flows are refused, so the window covers a shorter
    span than it claims -- volume features become floors and rate features
    underestimates.  Such windows carry ``evidence["truncated"] = True`` so a
    downstream consumer can see the number is a lower bound.

``max_sources``
    A cap on concurrently tracked source addresses, evicted least-recently-active
    first.  Eviction drains the source first, so no ready window is lost.

``max_buffered_flows``
    A global ceiling across all sources, which is what actually bounds memory:
    ``max_flows_per_source * max_sources`` is not a usable bound.  A buffered
    ``Flow`` measures 405 bytes on this corpus, so the default is about 405 MB in
    the worst case.  When the ceiling is reached the arriving flow is refused,
    which lands the refusals on whichever source is generating the load.

Setting the per-source cap from measurement, not intuition
----------------------------------------------------------
The first default here was 100,000, chosen against the laboratory's widest window
(14,556 connections).  It was wrong.  Uncapped peak buffered flows for one source:

===========================================  =========  ==========  =============
capture                                          flows   peak held   max window
===========================================  =========  ==========  =============
ctu-idseval-6-malicious-portscan-3             131,150     118,577         47,249
r5_scan_a (laboratory, widest)                  72,776      36,390         14,556
r2_scan_a (laboratory)                          38,912      18,432          6,144
ctu-idseval-6-malicious-malware-2              185,506       1,013          1,001
ctu-idseval-6-benign-user-traffic-1             35,046         201             45
===========================================  =========  ==========  =============

A real CTU scanner opened 47,249 connections inside a single 30-second window, so
100,000 truncated a legitimate scan -- the one traffic pattern this component
exists to measure.  A safety valve that engages on real data is not a safety
valve.  The default is now 250,000, above the observed 118,577 with headroom.

This bound cannot be made unconditional: masscan-class rates exceed any buffer.
What the caps guarantee is that the component degrades measurably rather than
exhausting memory, and that a truncated window says so.

Abstention is preserved
-----------------------
A window holding fewer than ``min_flows`` connections is not emitted, exactly as
in batch: with four connections there is no behavioural evidence either way.
Streaming counts these in ``StreamStats.windows_abstained`` because "how often
does the component decline to decide" is a real operational number that batch
extraction throws away.
"""

from __future__ import annotations

import dataclasses
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from .features import MIN_FLOWS, Flow, Window, WindowSpec, compute_window, window_offsets

# Two window widths.  Covers the laboratory's worst observed lag (5.00 s) twelve
# times over while bounding retention at 90 s per source.  It does NOT cover real
# traffic's tail, which is unbounded; see the module docstring.  Raising it trades
# memory and alert delay for fewer late drops, and the trade is measurable with
# verify_streaming_parity.py --lateness.
DEFAULT_LATENESS_SECONDS = 60.0

# Above the 118,577 flows one real CTU scanner required, with headroom.
DEFAULT_MAX_FLOWS_PER_SOURCE = 250_000
DEFAULT_MAX_SOURCES = 4_096
# ~405 MB at the measured 405 bytes per buffered flow.
DEFAULT_MAX_BUFFERED_FLOWS = 1_000_000


@dataclass
class StreamStats:
    """Counters describing what the stream did, including what it lost.

    Kept separate from the windows themselves so a caller can report health
    without inspecting output, and so nothing that was dropped is invisible.
    """

    flows_admitted: int = 0
    flows_late: int = 0
    flows_partly_late: int = 0
    # Two refusal counters rather than one: a single source outrunning its own cap
    # and total load outrunning the process are different operational problems
    # with different responses, and one combined number hides which happened.
    flows_refused_source: int = 0
    flows_refused_global: int = 0
    windows_emitted: int = 0
    windows_abstained: int = 0
    windows_truncated: int = 0
    sources_seen: int = 0
    sources_evicted: int = 0
    late_by_source: Counter = field(default_factory=Counter)

    @property
    def flows_refused(self) -> int:
        return self.flows_refused_source + self.flows_refused_global

    def report(self) -> list[str]:
        lines = [
            f"flows admitted        {self.flows_admitted:,}",
            f"flows dropped (late)  {self.flows_late:,}",
            f"flows partly late     {self.flows_partly_late:,}  (missed >=1 window)",
            f"flows refused         {self.flows_refused:,}  "
            f"(source cap {self.flows_refused_source:,}, "
            f"global cap {self.flows_refused_global:,})",
            f"windows emitted       {self.windows_emitted:,}",
            f"windows abstained     {self.windows_abstained:,}  (< min_flows)",
            f"windows truncated     {self.windows_truncated:,}",
            f"sources seen          {self.sources_seen:,}",
            f"sources evicted       {self.sources_evicted:,}",
        ]
        if self.late_by_source:
            worst = ", ".join(f"{ip} {count:,}"
                              for ip, count in self.late_by_source.most_common(5))
            lines.append(f"late flows by source  {worst}")
        return lines


class _SourceState:
    """Per-source buffer and window cursor.

    ``cursor`` is the lowest grid index not yet decided for this source.  It only
    ever advances, which is what makes a window impossible to emit twice.
    """

    __slots__ = ("flows", "cursor", "high_ts", "last_activity", "truncated")

    def __init__(self) -> None:
        self.flows: list[Flow] = []
        self.cursor: int | None = None
        self.high_ts = float("-inf")
        self.last_activity = float("-inf")
        # Set when a flow was refused for this source, so the windows that were
        # short a flow can be labelled.  Cleared once the affected windows are out.
        self.truncated = False


class StreamingWindower:
    """Turn a flow stream into windows, incrementally and in bounded memory.

    Windows are computed per source address and never across sources, matching
    batch extraction, which is also what makes the laboratory's per-container
    captures equivalent to a merged one.

    A window is released when the stream's watermark -- the highest timestamp seen
    so far, less the lateness allowance -- passes the window's end.  So output lags
    the traffic by roughly ``lateness_seconds``, and that lag is the price of not
    emitting a verdict on a window that is still filling up.

    Usage::

        windower = StreamingWindower()
        for flow in open_source("zeek-tail:/opt/zeek/logs/current/conn.log"):
            for window in windower.push(flow):
                ...
        for window in windower.flush():   # end of stream: release everything held
            ...
    """

    def __init__(
        self,
        spec: WindowSpec = WindowSpec(),
        lateness_seconds: float = DEFAULT_LATENESS_SECONDS,
        max_flows_per_source: int = DEFAULT_MAX_FLOWS_PER_SOURCE,
        max_sources: int = DEFAULT_MAX_SOURCES,
        max_buffered_flows: int = DEFAULT_MAX_BUFFERED_FLOWS,
        stats: StreamStats | None = None,
    ) -> None:
        if lateness_seconds < 0:
            raise ValueError("lateness_seconds must not be negative")
        if max_flows_per_source < spec.min_flows:
            raise ValueError("max_flows_per_source below min_flows would abstain always")
        if max_sources < 1:
            raise ValueError("max_sources must be at least 1")
        if max_buffered_flows < spec.min_flows:
            raise ValueError("max_buffered_flows below min_flows would abstain always")
        self.spec = spec
        self.lateness_seconds = lateness_seconds
        self.max_flows_per_source = max_flows_per_source
        self.max_sources = max_sources
        self.max_buffered_flows = max_buffered_flows
        self.stats = stats if stats is not None else StreamStats()
        # Insertion-ordered, and re-inserted on activity, so the first key is
        # always the least-recently-active source.
        self._sources: dict[str, _SourceState] = {}
        self._watermark_source = float("-inf")
        # Maintained incrementally.  Summing over sources on every flow would make
        # ingest cost scale with the number of tracked addresses.
        self._buffered = 0
        # ceil(window / stride): how many grid windows any one flow belongs to.
        self._span = len(window_offsets(spec))

    # ------------------------------------------------------------------- ingest

    def push(self, flow: Flow) -> list[Window]:
        """Admit one flow; return whatever windows that made releasable.

        Returns a list rather than a generator on purpose: a caller who forgets to
        consume a generator would silently stall the whole pipeline.
        """
        state = self._sources.get(flow.src_ip)
        if state is None:
            state = _SourceState()
            self._sources[flow.src_ip] = state
            self.stats.sources_seen += 1
        else:
            # Move to the back of the LRU order.
            self._sources[flow.src_ip] = self._sources.pop(flow.src_ip)

        self._watermark_source = max(self._watermark_source, flow.ts)
        state.high_ts = max(state.high_ts, flow.ts)
        state.last_activity = self._watermark_source

        # A flow belongs to `_span` consecutive windows, so lateness is not
        # all-or-nothing.  It is fully lost only once EVERY window containing it
        # has been decided, which is exactly when its start precedes the oldest
        # window still open.  The alternative -- re-emitting a revised window --
        # pushes correction handling onto every downstream consumer for the sake
        # of long-lived sessions that contribute one connection each.
        if state.cursor is not None:
            if self._last_window_index_of(flow.ts) < state.cursor:
                self.stats.flows_late += 1
                self.stats.late_by_source[flow.src_ip] += 1
                return []
            if self._window_index_of(flow.ts) < state.cursor:
                # Placed in its remaining windows but missing from at least one
                # already emitted.  Counted separately because it degrades a
                # window rather than losing a flow, and the two are not the same
                # failure when reconciling against batch extraction.
                self.stats.flows_partly_late += 1

        if len(state.flows) >= self.max_flows_per_source:
            self.stats.flows_refused_source += 1
            state.truncated = True
            return []
        if self._buffered >= self.max_buffered_flows:
            self.stats.flows_refused_global += 1
            state.truncated = True
            return []

        state.flows.append(flow)
        self._buffered += 1
        self.stats.flows_admitted += 1

        released = self._release(flow.src_ip, state, self._watermark())
        released.extend(self._enforce_source_cap())
        return released

    def flush(self) -> list[Window]:
        """Release every window still held, ignoring the lateness allowance.

        Correct at end of stream, where nothing further can arrive.  On a live
        tail this discards the guarantee that a window is complete, so call it
        only when the source really has ended.
        """
        released: list[Window] = []
        for src_ip in list(self._sources):
            state = self._sources.pop(src_ip)
            released.extend(self._release(src_ip, state, float("inf")))
        return released

    def tick(self, now_ts: float) -> list[Window]:
        """Release windows already complete as of wall-clock ``now_ts``.

        ``push`` only advances the watermark and releases windows when a flow
        arrives.  On a live tail traffic can stop the instant an attack ends (a
        port scan is a burst, then silence), which freezes the packet-time
        watermark and leaves the final, fully-populated window held forever.

        A wall-clock-driven caller (a window-boundary loop) calls ``tick`` with
        the current time so the effective watermark keeps advancing in real time.
        Packet timestamps from a live sniffer are wall-clock, so once ``now_ts``
        is more than ``lateness_seconds`` past a window's end, that window is
        complete and released -- without the all-or-nothing semantics of
        ``flush`` (still-filling windows stay held).
        """
        self._watermark_source = max(self._watermark_source, now_ts)
        watermark = self._watermark()
        released: list[Window] = []
        for src_ip in list(self._sources):
            state = self._sources[src_ip]
            released.extend(self._release(src_ip, state, watermark))
        return released

    def windows(self, flows: Iterable[Flow]) -> Iterator[Window]:
        """Convenience: stream a finite iterable through and drain at the end."""
        for flow in flows:
            yield from self.push(flow)
        yield from self.flush()

    # -------------------------------------------------------------- windowing

    def _watermark(self) -> float:
        return self._watermark_source - self.lateness_seconds

    def _window_index_of(self, timestamp: float) -> int:
        """Lowest grid index of a window containing ``timestamp``.

        The same arithmetic as ``features.candidate_window_indices``: a flow
        belongs to ``_span`` consecutive windows, of which this is the earliest.
        Sharing the formula is what keeps the streaming grid on the training grid.
        """
        return math.floor(timestamp / self.spec.stride_seconds) - (self._span - 1)

    def _last_window_index_of(self, timestamp: float) -> int:
        """Highest grid index of a window containing ``timestamp``."""
        return math.floor(timestamp / self.spec.stride_seconds)

    def _release(self, src_ip: str, state: _SourceState, watermark: float) -> list[Window]:
        """Emit every window for one source that the watermark has passed."""
        released: list[Window] = []
        while state.flows:
            # Anchor on the oldest buffered flow rather than walking the grid from
            # the last cursor.  CTU's malware captures span weeks; without this a
            # single idle gap would step through millions of empty windows.
            anchor = self._window_index_of(min(flow.ts for flow in state.flows))
            cursor = anchor if state.cursor is None else max(state.cursor, anchor)
            start = cursor * self.spec.stride_seconds
            end = start + self.spec.window_seconds
            if end > watermark:
                state.cursor = cursor
                break

            # Filtered in arrival order, then stable-sorted by timestamp, which
            # reproduces batch extraction's flow sequence exactly.  Order matters
            # only through float summation, but a differently-ordered sum can
            # change the sixth decimal place, and that would show up as a spurious
            # streaming/batch mismatch.
            members = sorted((flow for flow in state.flows if start <= flow.ts < end),
                             key=lambda flow: flow.ts)
            window = compute_window(members, start, end, self.spec)
            if window is None:
                if members:
                    self.stats.windows_abstained += 1
            else:
                if state.truncated:
                    window = dataclasses.replace(
                        window, evidence={**window.evidence, "truncated": True})
                    self.stats.windows_truncated += 1
                released.append(window)
                self.stats.windows_emitted += 1

            state.cursor = cursor + 1
            # Anything starting before the next window's start can never be needed
            # again, because the cursor only advances.
            horizon = state.cursor * self.spec.stride_seconds
            kept = [flow for flow in state.flows if flow.ts >= horizon]
            self._buffered -= len(state.flows) - len(kept)
            state.flows = kept
            if not state.flows:
                state.truncated = False
        return released

    def _enforce_source_cap(self) -> list[Window]:
        """Drain and drop the least-recently-active sources over the cap."""
        released: list[Window] = []
        while len(self._sources) > self.max_sources:
            src_ip, state = next(iter(self._sources.items()))
            del self._sources[src_ip]
            # Drained, not discarded: an evicted source's buffered flows are
            # complete as far as this stream is concerned, so their windows are
            # legitimate output.  Dropping them silently would lose detections
            # precisely under the load that triggers eviction.
            released.extend(self._release(src_ip, state, float("inf")))
            self.stats.sources_evicted += 1
        return released

    # ------------------------------------------------------------------ status

    def buffered_flows(self) -> int:
        return self._buffered

    def tracked_sources(self) -> int:
        return len(self._sources)


def stream_windows(
    flows: Iterable[Flow],
    spec: WindowSpec = WindowSpec(),
    lateness_seconds: float = DEFAULT_LATENESS_SECONDS,
    stats: StreamStats | None = None,
    **limits,
) -> Iterator[Window]:
    """Window a flow iterable through the streaming path.

    The function form exists so a caller that does not need the windower's counters
    or mid-stream state can treat streaming and batch as interchangeable, which is
    what the parity check relies on.
    """
    windower = StreamingWindower(spec=spec, lateness_seconds=lateness_seconds,
                                 stats=stats, **limits)
    yield from windower.windows(flows)


if __name__ == "__main__":  # pragma: no cover - smoke check
    import sys
    from pathlib import Path

    from .sources import SourceStats, zeek_conn_log

    if len(sys.argv) < 2:
        raise SystemExit("usage: python -m portscan.streaming <conn.log>")
    source_stats, stream_stats = SourceStats(), StreamStats()
    windower = StreamingWindower(stats=stream_stats)
    peak_flows = peak_sources = 0
    emitted = 0
    for record in zeek_conn_log(Path(sys.argv[1]), source_stats):
        emitted += len(windower.push(record))
        peak_flows = max(peak_flows, windower.buffered_flows())
        peak_sources = max(peak_sources, windower.tracked_sources())
    emitted += len(windower.flush())
    print(f"windows emitted: {emitted:,}   min_flows={MIN_FLOWS}")
    print(f"peak buffered flows: {peak_flows:,}   peak tracked sources: {peak_sources:,}")
    print("\n".join(stream_stats.report()))
    print("\n".join(source_stats.report()))
