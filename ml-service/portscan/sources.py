#!/usr/bin/env python3
"""Flow-source adapters: network metadata in, :class:`Flow` objects out.

Every adapter yields the same ``Iterator[Flow]``, so the windower, the model and
the alert emitter are all indifferent to where a flow came from.  That is what
lets one component serve offline training extraction and live inference without a
second feature implementation.

Adapters, in order of how the SIH pipeline is expected to use them:

``zeek_conn_log``
    Read or **tail** a Zeek ``conn.log``, JSON or TSV, autodetected.  This is the
    primary adapter: the real system runs Zeek already, and JSON Streaming Logs is
    the normal way to hand its output to another process.
``pcap_replay``
    Run Zeek over a PCAP inside the ``zeek/zeek`` container and stream the
    resulting flows, optionally paced against the wall clock so that streaming
    behaviour can be exercised without live traffic.
``tshark_live`` / ``tshark_pcap``
    Aggregate TShark per-packet output into flows where Zeek is unavailable.
    Approximate -- see the function docstring -- and not the reference path.

Safety
------
Everything here is PASSIVE.  These adapters read logs, files, and (for TShark) a
capture handle; not one of them emits a packet.  Scan *generation* lives entirely
in the throwaway Docker ``--internal`` bridge under ``scripts/`` and
``data/self-generated/lab2/gen/``, and nothing in this module can reach it.
Reading a live interface is therefore fine here: observing traffic and generating
traffic are different acts.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .features import Flow

# Zeek's placeholders for "no value" and "empty container".
MISSING_TOKENS = frozenset({"-", "(empty)", ""})

# The fields the feature code needs.  An adapter that cannot supply all of these
# is rejected at open time rather than silently yielding zeros.
REQUIRED_ZEEK_FIELDS = (
    "ts", "id.orig_h", "id.resp_h", "id.resp_p", "conn_state",
    "duration", "orig_pkts", "resp_pkts", "history",
)

ZEEK_IMAGE = "zeek/zeek"


# --------------------------------------------------------------------- counters

@dataclass
class SourceStats:
    """Data-quality counters, surfaced rather than swallowed.

    A malformed field becomes 0.0 so that one bad line cannot abort a live
    detector, but the substitution is always counted.  Silent coercion is how a
    feature table quietly stops meaning what it claims to.
    """

    problems: Counter = field(default_factory=Counter)
    flows: int = 0

    def note(self, key: str) -> None:
        self.problems[key] += 1

    def report(self) -> str:
        if not self.problems:
            return f"{self.flows:,} flows, no data-quality problems"
        detail = ", ".join(f"{key}={value:,}" for key, value in sorted(self.problems.items()))
        return f"{self.flows:,} flows; {detail}"


def _number(value: str, stats: SourceStats, key: str) -> float:
    """Coerce a Zeek numeric field, counting anything missing or unparseable."""
    if value in MISSING_TOKENS:
        stats.note(f"missing {key}")
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        stats.note(f"unparseable {key}")
        return 0.0


def _text(value: object) -> str:
    """Normalise an optional string field to Zeek's own empty marker."""
    if value is None:
        return "-"
    return str(value)


# Zeek's ASCII writer prints `time` and `interval` values to six decimal places;
# its JSON writer emits the full double.  So the same connection read as TSV and as
# JSON gives durations like 0.000702 and 0.000701904296875.  Both parsers round to
# the ASCII precision so that the two formats produce byte-identical Flow objects.
#
# This is not cosmetic.  Every feature table on disk came from TSV, while the live
# primary adapter reads JSON; without this, a feature that used duration or
# timestamps at full precision would compute one value in training and another in
# the field.  `avg_duration` happens to round the difference away today, which is
# exactly the kind of accident that stops being true when a feature is added.
ZEEK_ASCII_PRECISION = 6


# ------------------------------------------------------------- Zeek TSV and JSON

def parse_zeek_tsv(lines: Iterable[str], stats: SourceStats, origin: str = "conn.log") -> Iterator[Flow]:
    """Parse Zeek TSV, driven by the ``#fields`` header.

    Column positions are never assumed: Zeek's column set depends on which scripts
    are loaded, so a fixed-index parser silently misreads any log produced by a
    differently configured Zeek.  This mirrors ``extract_features_v3.parse_zeek_log``
    exactly, including its error behaviour, so v3 and v4 tables are comparable.

    Written as a generator over lines rather than a whole-file read so the same
    code serves a closed file and an open tail.
    """
    fields: list[str] | None = None
    validated = False

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                missing = set(REQUIRED_ZEEK_FIELDS).difference(fields)
                if missing:
                    raise ValueError(f"{origin}: missing required fields {sorted(missing)}")
                validated = True
            continue
        if fields is None:
            raise ValueError(f"{origin}: data appeared before #fields")
        values = line.split("\t")
        if len(values) != len(fields):
            stats.note(f"{origin}: field-count mismatch")
            continue
        record = dict(zip(fields, values))
        stats.flows += 1
        yield _flow_from_zeek_record(record, stats)

    if not validated:
        # A log that never declared its columns cannot be trusted; an empty file is
        # the one benign case and is reported rather than raised, because an idle
        # source legitimately produces one.
        if stats.flows == 0:
            stats.note(f"{origin}: no #fields header (empty log?)")
        else:
            raise ValueError(f"{origin}: no #fields header")


def parse_zeek_json(lines: Iterable[str], stats: SourceStats, origin: str = "conn.log") -> Iterator[Flow]:
    """Parse Zeek JSON Streaming Logs: one JSON object per line.

    JSON mode omits absent fields entirely rather than writing ``-``, so absence is
    normal and is counted through the same path as a ``-`` in TSV.  A line that is
    not valid JSON is counted and skipped: in a tail, a partially flushed line is
    an expected transient, and killing a live detector over one is wrong.
    """
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            stats.note(f"{origin}: unparseable JSON line")
            continue
        if not isinstance(record, dict):
            stats.note(f"{origin}: JSON line is not an object")
            continue
        stats.flows += 1
        yield _flow_from_zeek_record(record, stats)


def _flow_from_zeek_record(record: dict, stats: SourceStats) -> Flow:
    """Build a :class:`Flow` from one Zeek record, TSV or JSON.

    Shared by both parsers so that a JSON log and the TSV of the same traffic
    produce identical flows -- otherwise the choice of Zeek output format would
    change the features, and the primary adapter would not be validated by the
    offline tables.
    """
    return Flow(
        # Rounded to Zeek's ASCII precision so a JSON log and the TSV of the same
        # traffic yield identical flows; see ZEEK_ASCII_PRECISION.
        ts=round(_number(_text(record.get("ts")), stats, "timestamp"), ZEEK_ASCII_PRECISION),
        src_ip=_text(record.get("id.orig_h")),
        dst_ip=_text(record.get("id.resp_h")),
        # Kept as text: a port is a grouping key here, never a magnitude.  JSON
        # mode gives an int, TSV a string; normalising to text makes the two agree.
        dst_port=_text(record.get("id.resp_p")),
        conn_state=_text(record.get("conn_state")),
        duration=round(
            _number(_text(record.get("duration")), stats, "duration"), ZEEK_ASCII_PRECISION
        ),
        orig_pkts=_number(_text(record.get("orig_pkts")), stats, "orig_pkts"),
        resp_pkts=_number(_text(record.get("resp_pkts")), stats, "resp_pkts"),
        history=_text(record.get("history")),
    )


def sniff_zeek_format(path: Path) -> str:
    """Decide TSV or JSON from the first non-blank line.

    Zeek's own marker is unambiguous: TSV logs open with ``#separator``, JSON logs
    with ``{``.  Guessing from the filename would be wrong, since both formats are
    written to ``conn.log``.
    """
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("{"):
                return "json"
            if line.startswith("#"):
                return "tsv"
            raise ValueError(f"{path.name}: first line is neither Zeek TSV nor JSON")
    return "json"  # Empty file: assume the streaming format and yield nothing.


def follow_lines(
    path: Path,
    from_start: bool = True,
    poll_seconds: float = 0.5,
    idle_timeout: float | None = None,
) -> Iterator[str]:
    """Yield lines from a growing file, blocking for more.

    Handles the two things that break a naive tail against a live Zeek:

    * **Partial lines.** Zeek's writer is not atomic per line, so a read can land
      mid-line.  Anything without a trailing newline is held back until the rest
      arrives, because half a JSON object is not a flow.
    * **Rotation.** Zeek rotates ``conn.log`` on its own schedule.  A file that
      shrinks, or whose identity changes, has been rotated, so the handle is
      reopened from the top rather than blocking forever on a file nobody writes
      to any more.

    ``idle_timeout`` bounds the wait for new data and exists so that a bounded run
    can terminate; ``None`` follows indefinitely.
    """
    handle = path.open(encoding="utf-8", errors="replace")
    try:
        if not from_start:
            handle.seek(0, os.SEEK_END)
        pending = ""
        idle_for = 0.0
        marker = _file_identity(path)

        while True:
            chunk = handle.read()
            if chunk:
                idle_for = 0.0
                pending += chunk
                *complete, pending = pending.split("\n")
                for line in complete:
                    yield line
                continue

            if _rotated(path, handle, marker):
                handle.close()
                handle = path.open(encoding="utf-8", errors="replace")
                marker = _file_identity(path)
                pending = ""
                continue

            if idle_timeout is not None and idle_for >= idle_timeout:
                if pending.strip():
                    yield pending  # Final line, written without a newline.
                return
            time.sleep(poll_seconds)
            idle_for += poll_seconds
    finally:
        handle.close()


def _file_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.stat()
    except OSError:
        return None
    # st_ino is 0 on some Windows filesystems, so size is carried alongside it and
    # a shrink is treated as rotation regardless of inode support.
    return (info.st_ino, info.st_dev)


def _rotated(path: Path, handle, marker: tuple[int, int] | None) -> bool:
    try:
        info = path.stat()
    except OSError:
        return False
    if handle.tell() > info.st_size:
        return True
    return marker is not None and (info.st_ino, info.st_dev) != marker


def zeek_conn_log(
    path: str | Path,
    stats: SourceStats | None = None,
    follow: bool = False,
    log_format: str | None = None,
    from_start: bool = True,
    idle_timeout: float | None = None,
) -> Iterator[Flow]:
    """Primary adapter: flows from a Zeek ``conn.log``, batch or tailed.

    ``follow=False`` reads the file once and stops -- the offline extraction path.
    ``follow=True`` tails it, which is how the component runs beside a live Zeek.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"No Zeek conn.log at {path}")
    stats = stats if stats is not None else SourceStats()
    resolved = log_format or sniff_zeek_format(path)

    if follow:
        lines: Iterable[str] = follow_lines(
            path, from_start=from_start, idle_timeout=idle_timeout
        )
    else:
        lines = _read_lines(path)

    parser = parse_zeek_json if resolved == "json" else parse_zeek_tsv
    yield from parser(lines, stats, origin=path.name)


def _read_lines(path: Path) -> Iterator[str]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        yield from handle


# ------------------------------------------------------------------ PCAP replay

def zeek_over_pcap(
    pcap: str | Path,
    out_dir: str | Path,
    docker_image: str = ZEEK_IMAGE,
    json_logs: bool = False,
) -> Path:
    """Run ``zeek -C -r`` over one PCAP in a container; return the ``conn.log``.

    Deliberately the same invocation as ``data/self-generated/lab2/gen/zeek_batch.sh``,
    which processes both the lab captures and the CTU PCAPs, so a replayed PCAP
    passes through the same tooling as the training corpus.  ``-C`` is required
    because Docker's virtual NICs offload checksums, which Zeek would otherwise
    reject as bad.

    The PCAP directory is mounted read-only, so an input capture cannot be
    modified by this call.
    """
    pcap = Path(pcap).resolve()
    if not pcap.is_file():
        raise FileNotFoundError(f"No PCAP at {pcap}")
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if shutil.which("docker") is None:
        raise RuntimeError("docker is not on PATH; PCAP replay needs the zeek/zeek image")

    script = (
        "set -e; cd /out; "
        + ("zeek -C -r /pcap/%s LogAscii::use_json=T" % pcap.name if json_logs
           else "zeek -C -r /pcap/%s" % pcap.name)
    )
    command = [
        "docker", "run", "--rm",
        "-v", f"{pcap.parent}:/pcap:ro",
        "-v", f"{out_dir}:/out",
        "--entrypoint", "sh", docker_image, "-c", script,
    ]
    # MSYS_NO_PATHCONV: under Git Bash, MSYS rewrites the `/pcap` and `/out`
    # halves of a -v argument into Windows paths, and Docker Desktop then fails
    # the mount silently rather than erroring.
    environment = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    result = subprocess.run(command, capture_output=True, text=True, env=environment)
    if result.returncode != 0:
        raise RuntimeError(
            f"Zeek failed on {pcap.name} (exit {result.returncode}):\n"
            f"{result.stderr.strip() or result.stdout.strip()}"
        )

    conn_log = out_dir / "conn.log"
    if not conn_log.exists():
        raise RuntimeError(
            f"Zeek produced no conn.log for {pcap.name}; the capture may hold no TCP/UDP"
        )
    return conn_log


def pcap_replay(
    pcap: str | Path,
    work_dir: str | Path,
    stats: SourceStats | None = None,
    speed: float = 0.0,
    docker_image: str = ZEEK_IMAGE,
) -> Iterator[Flow]:
    """Stream a PCAP's flows in timestamp order, optionally paced to the clock.

    ``speed=0.0`` yields as fast as possible -- the right choice for evaluation,
    where reproducibility matters and wall-clock pacing only adds hours.
    ``speed=1.0`` replays in real time and higher values compress it, which is how
    the streaming path gets exercised end-to-end without live traffic.

    Pacing is applied to the *gaps between flows*, so a capture with a long idle
    stretch replays that stretch; this is intentional, since a detector that only
    ever sees dense traffic has not been tested against the sparse case.
    """
    stats = stats if stats is not None else SourceStats()
    conn_log = zeek_over_pcap(pcap, work_dir, docker_image=docker_image)
    flows = sorted(zeek_conn_log(conn_log, stats), key=lambda flow: flow.ts)

    if speed <= 0:
        yield from flows
        return

    origin_ts = flows[0].ts if flows else 0.0
    started = time.monotonic()
    for flow in flows:
        target = (flow.ts - origin_ts) / speed
        delay = target - (time.monotonic() - started)
        if delay > 0:
            time.sleep(delay)
        yield flow


# ----------------------------------------------------------------------- TShark

# TShark reports TCP flags per packet; Zeek reports a connection state.  This maps
# the flag combinations we can observe onto the Zeek states the model was trained
# on.  It is an APPROXIMATION and the mapping is the honest weak point of this
# adapter: Zeek's state machine also uses timers, byte counts and direction
# tracking that per-packet flags alone cannot reconstruct.  Use Zeek where it is
# available; this exists for hosts where it is not.
TSHARK_FIELDS = (
    "frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport", "udp.dstport",
    "tcp.flags", "ip.proto",
)


def tshark_pcap(
    pcap: str | Path,
    stats: SourceStats | None = None,
    tshark_binary: str = "tshark",
) -> Iterator[Flow]:
    """Approximate flows from a PCAP via TShark, for hosts without Zeek."""
    pcap = Path(pcap).resolve()
    if not pcap.is_file():
        raise FileNotFoundError(f"No PCAP at {pcap}")
    yield from _tshark_flows(
        [tshark_binary, "-r", str(pcap), "-T", "fields", "-E", "separator=\t",
         *_field_args(), "-Y", "tcp or udp"],
        stats if stats is not None else SourceStats(),
        origin=pcap.name,
    )


def tshark_live(
    interface: str,
    stats: SourceStats | None = None,
    duration_seconds: int | None = None,
    tshark_binary: str = "tshark",
) -> Iterator[Flow]:
    """Approximate flows from a live interface via TShark.

    Passive capture only: TShark is invoked in read mode and emits nothing onto
    the wire.  Requires whatever capture privilege the host demands, which is the
    operator's decision, not this code's.
    """
    command = [tshark_binary, "-i", interface, "-l", "-T", "fields",
               "-E", "separator=\t", *_field_args(), "-Y", "tcp or udp"]
    if duration_seconds:
        command += ["-a", f"duration:{duration_seconds}"]
    yield from _tshark_flows(
        command, stats if stats is not None else SourceStats(), origin=f"iface:{interface}"
    )


def _field_args() -> list[str]:
    return [item for name in TSHARK_FIELDS for item in ("-e", name)]


def _tshark_flows(command: list[str], stats: SourceStats, origin: str) -> Iterator[Flow]:
    """Aggregate TShark packets into flows, emitting each when it is decided.

    A flow is emitted as soon as its state is unambiguous -- a RST or a FIN -- and
    anything still open at end of capture is emitted with the state implied by what
    was seen.  Holding every flow until the end would defeat the streaming purpose
    of the adapter.
    """
    if shutil.which(command[0]) is None:
        raise RuntimeError(f"{command[0]} is not on PATH")

    open_flows: dict[tuple[str, str, str, str], dict] = {}
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    try:
        for line in process.stdout or ():
            parsed = _tshark_packet(line, stats, origin)
            if parsed is None:
                continue
            key, timestamp, flags, proto = parsed
            record = open_flows.get(key)
            if record is None:
                record = open_flows[key] = {
                    "first_ts": timestamp, "last_ts": timestamp,
                    "orig_pkts": 0.0, "resp_pkts": 0.0,
                    "syn": False, "syn_ack": False, "rst": False, "fin": False,
                    "proto": proto,
                }
            record["last_ts"] = timestamp
            record["orig_pkts"] += 1.0
            if flags is not None:
                record["syn"] |= bool(flags & 0x02)
                record["rst"] |= bool(flags & 0x04)
                record["fin"] |= bool(flags & 0x01)
                record["syn_ack"] |= (flags & 0x12) == 0x12

            reverse = (key[1], key[0], key[2], key[3])
            peer = open_flows.get(reverse)
            if peer is not None:
                peer["resp_pkts"] += 1.0
                if flags is not None and (flags & 0x12) == 0x12:
                    peer["syn_ack"] = True

            if flags is not None and (flags & 0x04 or flags & 0x01):
                stats.flows += 1
                yield _tshark_flow(key, open_flows.pop(key))

        for key, record in list(open_flows.items()):
            stats.flows += 1
            yield _tshark_flow(key, record)
    finally:
        if process.poll() is None:
            process.terminate()
        if process.stdout:
            process.stdout.close()
        stderr = process.stderr.read() if process.stderr else ""
        if process.stderr:
            process.stderr.close()
        code = process.wait()
        if code not in (0, None) and stderr.strip():
            stats.note(f"{origin}: tshark exit {code}")


def _tshark_packet(
    line: str, stats: SourceStats, origin: str
) -> tuple[tuple[str, str, str, str], float, int | None, str] | None:
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) < len(TSHARK_FIELDS):
        parts += [""] * (len(TSHARK_FIELDS) - len(parts))
    epoch, src, dst, tcp_port, udp_port, flags_text, _proto = parts[:7]
    if not src or not dst:
        stats.note(f"{origin}: packet without IP addresses")
        return None
    port = tcp_port or udp_port
    if not port:
        return None
    proto = "tcp" if tcp_port else "udp"
    try:
        timestamp = float(epoch)
    except ValueError:
        stats.note(f"{origin}: unparseable frame timestamp")
        return None
    flags = None
    if flags_text:
        try:
            flags = int(flags_text, 16) if flags_text.startswith("0x") else int(flags_text)
        except ValueError:
            stats.note(f"{origin}: unparseable tcp.flags")
    # Ports can be comma-separated when TShark sees tunnelled layers; the outermost
    # is the one that matters here.
    return (src, dst, port.split(",")[0], proto), timestamp, flags, proto


def _tshark_flow(key: tuple[str, str, str, str], record: dict) -> Flow:
    """Map observed TCP flags onto the closest Zeek ``conn_state``.

    Only the states the model actually keys on are reconstructed:
    ``S0`` (SYN, nothing back), ``REJ`` (SYN answered with RST), ``RSTO``
    (established then reset by the originator), ``SF`` (established and closed
    cleanly).  ``OTH`` is used where the flags do not decide it, rather than
    guessing a state the features would then treat as meaningful.
    """
    src, dst, port, proto = key
    established = record["syn_ack"] or record["resp_pkts"] > 0
    if proto == "udp":
        state = "SF" if record["resp_pkts"] > 0 else "S0"
    elif record["syn"] and not established:
        state = "REJ" if record["rst"] else "S0"
    elif established and record["rst"]:
        state = "RSTO"
    elif established and record["fin"]:
        state = "SF"
    elif established:
        state = "OTH"
    else:
        state = "OTH"

    # `history` is Zeek-specific and cannot be reconstructed from flags.  A bare
    # "S" is emitted only where it is literally true (a lone SYN), so that
    # `syn_only_ratio` stays meaningful instead of being fabricated.
    history = "S" if state == "S0" and record["orig_pkts"] == 1 and proto == "tcp" else "-"
    return Flow(
        ts=record["first_ts"],
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        conn_state=state,
        duration=max(0.0, record["last_ts"] - record["first_ts"]),
        orig_pkts=record["orig_pkts"],
        resp_pkts=record["resp_pkts"],
        history=history,
    )


# -------------------------------------------------------------------- dispatcher

def open_source(spec: str, stats: SourceStats | None = None, **options) -> Iterator[Flow]:
    """Resolve a source specification to a flow iterator.

    Accepted forms::

        zeek:<path>          read a conn.log once (default for a bare path)
        zeek-tail:<path>     tail a conn.log; the live path
        pcap:<path>          Zeek over a PCAP, then stream its flows
        tshark:<path.pcap>   TShark over a PCAP
        iface:<name>         TShark on a live interface

    A bare path is treated as ``pcap:`` for ``.pcap``/``.pcapng`` and ``zeek:``
    otherwise, so the common cases need no prefix.
    """
    stats = stats if stats is not None else SourceStats()
    scheme, _, target = spec.partition(":")
    if not target:
        scheme, target = _infer_scheme(spec), spec

    if scheme == "zeek":
        return zeek_conn_log(target, stats, follow=False, **options)
    if scheme == "zeek-tail":
        return zeek_conn_log(target, stats, follow=True, **options)
    if scheme == "pcap":
        work_dir = options.pop("work_dir", None)
        if work_dir is None:
            raise ValueError("pcap: sources need work_dir for Zeek's output")
        return pcap_replay(target, work_dir, stats, **options)
    if scheme == "tshark":
        return tshark_pcap(target, stats, **options)
    if scheme == "iface":
        return tshark_live(target, stats, **options)
    raise ValueError(
        f"Unknown source scheme {scheme!r}; expected one of "
        "zeek, zeek-tail, pcap, tshark, iface"
    )


def _infer_scheme(spec: str) -> str:
    return "pcap" if Path(spec).suffix.lower() in {".pcap", ".pcapng"} else "zeek"


if __name__ == "__main__":  # Manual smoke check: summarise one source.
    if len(sys.argv) < 2:
        raise SystemExit("usage: python -m portscan.sources <source-spec>")
    counters = SourceStats()
    seen = Counter()
    for item in open_source(sys.argv[1], counters):
        seen[item.conn_state] += 1
    print(counters.report())
    for name, total in seen.most_common():
        print(f"  {name:<6} {total:>9,}")
