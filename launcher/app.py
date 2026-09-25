"""
Threat Detection Console - Windows desktop control panel for the SIH
AI-Based Cyber Threat Detection pipeline.

Two views, switchable from the top nav bar:
  * Control Panel - start/stop the pipeline, health, demo & attacks, console log
  * Dashboard     - embedded live SOC view with canvas charts (donut threat
                    distribution, alert-rate line chart, severity + source bars,
                    stat cards, live alert feed) reading the backend REST API.

Build into a standalone .exe with:  launcher/build.ps1
Run from source with:               python launcher/app.py
"""

import json
import math
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from collections import deque
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

APP_NAME = "UniGuard"
APP_VERSION = "2.1.0"

DASHBOARD_URL = "http://localhost:3000"
API_BASE = "http://localhost:8001"
BACKEND_HEALTH_URL = f"{API_BASE}/api/health"
BACKEND_STATS_URL = f"{API_BASE}/api/stats"
BACKEND_RECENT_URL = f"{API_BASE}/api/alerts/recent?limit=40"
BACKEND_CLEAR_URL = f"{API_BASE}/api/alerts/clear"

DEFAULT_TARGET = "192.168.56.101"

SERVICES = [
    ("Kafka", "kafka"),
    ("ML Inference", "ml-inference"),
    ("Feature Extractor", "feature-extractor"),
    ("Backend API", "backend"),
    ("Dashboard", "dashboard"),
    ("Ingest (batch job)", "ingest"),
]

# 6 attacks, one per detector
ATTACKS = [
    ("Port Scan", "portscan"),
    ("DDoS Flood", "ddos"),
    ("Data Exfil", "exfil"),
    ("C2 Beacon", "c2"),
    ("Encrypted Malware", "encmal"),
    ("DGA / DNS", "dga"),
]

# ---------------------------------------------------------------------------
# Design system
# ---------------------------------------------------------------------------

BG = "#0a0e14"           # app background (deep navy-black)
BG_ELEV = "#111721"      # elevated surface
PANEL = "#151c28"        # panel/card fill
PANEL_HI = "#1c2536"     # hover / raised
STROKE = "#232d40"       # subtle border
STROKE_HI = "#31405c"    # brighter border
INK = "#e6edf6"          # primary text
INK_DIM = "#8593a8"      # secondary text
INK_FAINT = "#5b6779"    # tertiary text

ACCENT = "#4c8dff"       # primary blue
ACCENT_HOVER = "#6aa1ff"
GREEN = "#3ddc97"
RED = "#ff5c6c"
AMBER = "#ffb648"
PURPLE = "#b47cff"
CYAN = "#3ad4e0"
PINK = "#ff79c6"

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH": "#ff8a4c",
    "MEDIUM": AMBER,
    "LOW": ACCENT,
    "UNKNOWN": INK_FAINT,
}

THREAT_COLORS = {
    "PortScan": ACCENT,
    "DDoS": RED,
    "DGA": PURPLE,
    "C2_BEACONING": AMBER,
    "EncryptedMalware": PINK,
    "DataExfiltration": CYAN,
    "UNKNOWN": INK_FAINT,
}

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def project_root() -> Path:
    if getattr(sys, "frozen", False):
        start = Path(sys.executable).resolve().parent
    else:
        start = Path(__file__).resolve().parent
    for candidate in [start, *start.parents]:
        if (candidate / "docker-compose.yml").exists():
            return candidate
    return start.parent


ROOT = project_root()


# ---------------------------------------------------------------------------
# Reusable flat "premium" button with hover/press states
# ---------------------------------------------------------------------------

class FlatButton(tk.Frame):
    def __init__(self, master, text, command=None, kind="default", icon="",
                 small=False, **kw):
        palette = {
            "default": (PANEL_HI, "#26324a", INK, STROKE_HI),
            "primary": (ACCENT, ACCENT_HOVER, "#08111f", ACCENT),
            "danger": ("#3a1d24", "#4d232d", RED, "#5c2a34"),
            "ghost": (PANEL, PANEL_HI, INK_DIM, STROKE),
        }
        self.base, self.hover, self.fg, self.border = palette.get(kind, palette["default"])
        super().__init__(master, bg=self.border, highlightthickness=0, **kw)
        pad_y = 5 if small else 8
        self._inner = tk.Frame(self, bg=self.base)
        self._inner.pack(fill="both", expand=True, padx=1, pady=1)
        label = (f"{icon}  {text}" if icon else text)
        self._label = tk.Label(
            self._inner, text=label, bg=self.base, fg=self.fg,
            font=("Segoe UI Semibold", 9 if small else 10),
            padx=12, pady=pad_y, cursor="hand2")
        self._label.pack(fill="both", expand=True)
        self._command = command
        for w in (self._inner, self._label):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._on_press)
            w.bind("<ButtonRelease-1>", self._on_release)

    def _set_bg(self, color):
        self._inner.configure(bg=color)
        self._label.configure(bg=color)

    def _on_enter(self, _e):
        self._set_bg(self.hover)

    def _on_leave(self, _e):
        self._set_bg(self.base)

    def _on_press(self, _e):
        self._set_bg(self.border)

    def _on_release(self, _e):
        self._set_bg(self.hover)
        if self._command:
            self._command()


# ---------------------------------------------------------------------------
# Background command runner
# ---------------------------------------------------------------------------

class CommandRunner:
    def __init__(self, log_queue: "queue.Queue[str]"):
        self.log_queue = log_queue

    def log(self, msg: str):
        self.log_queue.put(msg)

    def run_async(self, args, cwd=None, label=None, on_done=None):
        threading.Thread(target=self._run, args=(args, cwd, label, on_done),
                         daemon=True).start()

    def _run(self, args, cwd, label, on_done):
        label = label or " ".join(str(a) for a in args)
        self.log(f"$ {label}")
        # Force UTF-8 in child processes so scripts that print Unicode (arrows,
        # box-drawing, etc.) never crash on a legacy cp1252 console pipe.
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        try:
            proc = subprocess.Popen(
                args, cwd=cwd or str(ROOT), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                encoding="utf-8", errors="replace",
                creationflags=CREATE_NO_WINDOW, env=env)
            for line in proc.stdout:
                self.log(line.rstrip())
            proc.wait()
            self.log(f"[ok] {label}" if proc.returncode == 0
                     else f"[exit {proc.returncode}] {label}")
        except FileNotFoundError:
            self.log(f"[error] command not found: {args[0]}")
        except Exception as exc:  # noqa: BLE001
            self.log(f"[error] {exc}")
        finally:
            if on_done:
                on_done()


# ---------------------------------------------------------------------------
# HTTP / docker helpers
# ---------------------------------------------------------------------------

def http_get_json(url, timeout=2):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def http_post(url, timeout=3):
    try:
        req = urllib.request.Request(url, method="POST", data=b"")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 400
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def docker_all_containers():
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}|{{.State}}"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=5,
            creationflags=CREATE_NO_WINDOW)
        if out.returncode != 0:
            return None
        result = {}
        for line in out.stdout.splitlines():
            if "|" in line:
                name, state = line.split("|", 1)
                result[name.strip()] = state.strip()
        return result
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def compose_command():
    return ["docker", "compose"]


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class ThreatConsole(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"UniGuard  v{APP_VERSION}  — Cyber Threat Detection Console")
        self.configure(bg=BG)
        self.geometry("1200x800")
        self.minsize(1040, 700)

        self._apply_icon()

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.runner = CommandRunner(self.log_queue)
        self.service_labels = {}
        self.target_var = tk.StringVar(value=DEFAULT_TARGET)
        self.iface_var = tk.StringVar(value="Ethernet 2")
        self.pipeline_state = tk.StringVar(value="UNKNOWN")
        self.current_view = "control"

        # dashboard state
        self.card_vars = {k: tk.StringVar(value="0")
                          for k in ("total", "rate", "critical", "sources")}
        self.card_targets = {k: 0 for k in self.card_vars}      # animated targets
        self.card_display = {k: 0.0 for k in self.card_vars}
        self.rate_series = deque(maxlen=40)                     # for line chart
        self._last_total = None

        self._build_style()
        self._build_nav()
        self._build_views()
        self._show_view("control")

        self.after(100, self._drain_log)
        self.after(60, self._animate_cards)
        self._start_health_thread()
        self._start_dashboard_thread()

    # -- window icon ------------------------------------------------------
    def _apply_icon(self):
        ico = Path(__file__).resolve().parent / "assets" / "app.ico"
        if getattr(sys, "frozen", False):
            ico = Path(sys._MEIPASS) / "assets" / "app.ico"  # type: ignore[attr-defined]
        try:
            if ico.exists():
                self.iconbitmap(str(ico))
        except Exception:
            pass

    # -- styling ----------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        self.f_title = tkfont.Font(family="Segoe UI Semibold", size=14)
        self.f_h = tkfont.Font(family="Segoe UI Semibold", size=10)
        self.f_body = tkfont.Font(family="Segoe UI", size=10)
        self.f_small = tkfont.Font(family="Segoe UI", size=9)
        self.f_mono = tkfont.Font(family="Cascadia Mono", size=9)
        style.configure("Dark.Vertical.TScrollbar", background=PANEL_HI,
                        troughcolor=BG, bordercolor=BG, arrowcolor=INK_DIM)

    # -- nav bar ----------------------------------------------------------
    def _build_nav(self):
        nav = tk.Frame(self, bg=BG_ELEV, height=58)
        nav.pack(fill="x", side="top")
        nav.pack_propagate(False)
        tk.Frame(self, bg=STROKE, height=1).pack(fill="x")

        brand = tk.Frame(nav, bg=BG_ELEV)
        brand.pack(side="left", padx=(20, 28))
        tk.Label(brand, text="⛨", bg=BG_ELEV, fg=ACCENT,
                 font=("Segoe UI", 18)).pack(side="left", padx=(0, 8))
        tk.Label(brand, text="UniGuard", bg=BG_ELEV, fg=INK,
                 font=("Segoe UI Semibold", 13)).pack(side="left")
        tk.Label(brand, text="· Cyber Threat Detection", bg=BG_ELEV, fg=INK_DIM,
                 font=("Segoe UI", 11)).pack(side="left", padx=(6, 0))

        self.nav_buttons = {}
        self.nav_underlines = {}
        for key, label in [("control", "CONTROL PANEL"), ("dashboard", "DASHBOARD")]:
            holder = tk.Frame(nav, bg=BG_ELEV)
            holder.pack(side="left", padx=2)
            b = tk.Label(holder, text=label, bg=BG_ELEV, fg=INK_DIM,
                         font=("Segoe UI Semibold", 10), padx=16, pady=16,
                         cursor="hand2")
            b.pack()
            ul = tk.Frame(holder, bg=BG_ELEV, height=2)
            ul.pack(fill="x")
            b.bind("<Button-1>", lambda _e, k=key: self._show_view(k))
            b.bind("<Enter>", lambda _e, w=b, k=key:
                   w.configure(fg=INK) if self.current_view != k else None)
            b.bind("<Leave>", lambda _e, w=b, k=key:
                   w.configure(fg=INK_DIM) if self.current_view != k else None)
            self.nav_buttons[key] = b
            self.nav_underlines[key] = ul

        # right: pipeline status pill + quick-actions (terminal)
        pill = tk.Frame(nav, bg=PANEL, highlightbackground=STROKE,
                        highlightthickness=1)
        pill.pack(side="right", padx=(12, 20), pady=14)
        self.state_dot = tk.Label(pill, text="●", bg=PANEL, fg=INK_FAINT,
                                  font=("Segoe UI", 11))
        self.state_dot.pack(side="left", padx=(10, 4), pady=4)
        tk.Label(pill, textvariable=self.pipeline_state, bg=PANEL, fg=INK,
                 font=("Segoe UI Semibold", 9)).pack(side="left", padx=(0, 12))

        FlatButton(nav, "Terminal", self.on_open_terminal, icon="⌨",
                   small=True).pack(side="right", padx=(0, 4), pady=14)

    def _build_views(self):
        self.view_container = tk.Frame(self, bg=BG)
        self.view_container.pack(fill="both", expand=True)
        self.control_view = tk.Frame(self.view_container, bg=BG)
        self.dashboard_view = tk.Frame(self.view_container, bg=BG)
        self._build_control_view(self.control_view)
        self._build_dashboard_view(self.dashboard_view)

    def _show_view(self, key):
        self.current_view = key
        self.control_view.pack_forget()
        self.dashboard_view.pack_forget()
        (self.control_view if key == "control" else self.dashboard_view).pack(
            fill="both", expand=True)
        for k, btn in self.nav_buttons.items():
            active = k == key
            btn.configure(fg=ACCENT if active else INK_DIM)
            self.nav_underlines[k].configure(bg=ACCENT if active else BG_ELEV)

    # ==================================================================
    # CARD (shared)
    # ==================================================================
    def _card(self, parent, title=None):
        outer = tk.Frame(parent, bg=STROKE)
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        if title:
            head = tk.Frame(inner, bg=PANEL)
            head.pack(fill="x", padx=14, pady=(12, 6))
            tk.Frame(head, bg=ACCENT, width=3, height=14).pack(side="left", padx=(0, 8))
            tk.Label(head, text=title, bg=PANEL, fg=INK,
                     font=("Segoe UI Semibold", 10)).pack(side="left")
        return outer, inner

    # ==================================================================
    # CONTROL PANEL VIEW
    # ==================================================================
    def _build_control_view(self, parent):
        body = tk.Frame(parent, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=16)
        body.columnconfigure(0, weight=0, minsize=396)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Left column is scrollable so the demo/attack + capture controls are
        # always reachable regardless of window height.
        left_holder = tk.Frame(body, bg=BG, width=396)
        left_holder.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left_holder.grid_propagate(False)
        left = self._scrollable(left_holder)

        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")

        self._build_pipeline_panel(left)
        self._build_services_panel(left)
        self._build_demo_panel(left)
        self._build_log_panel(right)

    def _scrollable(self, parent):
        """Create a vertically-scrollable region; returns the inner frame to
        pack content into. Handles mouse-wheel scroll and dynamic scrollregion."""
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0, bd=0)
        vbar = tk.Scrollbar(parent, orient="vertical", command=canvas.yview,
                            width=10)
        canvas.configure(yscrollcommand=vbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        vbar.pack(side="right", fill="y")

        inner = tk.Frame(canvas, bg=BG)
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_config(_e=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _on_config)

        def _match_width(e):
            canvas.itemconfigure(window_id, width=e.width)
        canvas.bind("<Configure>", _match_width)

        # Mouse-wheel scrolling only while the cursor is over this region, and
        # only when there is actually overflow to scroll.
        def _on_wheel(e):
            bbox = canvas.bbox("all")
            if bbox and bbox[3] > canvas.winfo_height():
                canvas.yview_scroll(int(-e.delta / 120), "units")
            return "break"
        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", _on_wheel))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))
        return inner

    def _build_pipeline_panel(self, parent):
        outer, panel = self._card(parent, "PIPELINE CONTROL")
        outer.pack(fill="x", pady=(0, 14))
        row = tk.Frame(panel, bg=PANEL)
        row.pack(fill="x", padx=14, pady=(2, 8))
        FlatButton(row, "Start Pipeline", self.on_start, kind="primary",
                   icon="▶").pack(side="left", padx=(0, 6))
        FlatButton(row, "Stop", self.on_stop, kind="danger",
                   icon="■").pack(side="left", padx=(0, 6))
        FlatButton(row, "Rebuild", self.on_rebuild, icon="⟳").pack(side="left")
        row2 = tk.Frame(panel, bg=PANEL)
        row2.pack(fill="x", padx=14, pady=(0, 14))
        FlatButton(row2, "Open in Browser", lambda: webbrowser.open(DASHBOARD_URL),
                   icon="🖥").pack(side="left", padx=(0, 6))
        FlatButton(row2, "Clear Alerts", self.on_clear, kind="ghost",
                   icon="🧹").pack(side="left")

    def _build_services_panel(self, parent):
        outer, panel = self._card(parent, "SERVICE HEALTH")
        outer.pack(fill="x", pady=(0, 14))
        holder = tk.Frame(panel, bg=PANEL)
        holder.pack(fill="x", padx=14, pady=(2, 14))
        for label, container in SERVICES:
            row = tk.Frame(holder, bg=PANEL)
            row.pack(fill="x", pady=3)
            dot = tk.Label(row, text="●", bg=PANEL, fg=INK_FAINT, font=("Segoe UI", 11))
            dot.pack(side="left")
            tk.Label(row, text=label, bg=PANEL, fg=INK, font=self.f_body).pack(
                side="left", padx=8)
            state = tk.Label(row, text="unknown", bg=PANEL, fg=INK_DIM, font=self.f_small)
            state.pack(side="right")
            self.service_labels[container] = (dot, state)

    def _build_demo_panel(self, parent):
        outer, panel = self._card(parent, "DEMO & ATTACKS")
        outer.pack(fill="x", pady=(0, 14))
        pad = tk.Frame(panel, bg=PANEL)
        pad.pack(fill="x", padx=14, pady=(2, 14))

        FlatButton(pad, "Inject Synthetic Threats (no VM, no sniffer)",
                   self.on_inject, kind="primary", icon="💉").pack(fill="x")
        tk.Label(pad, text="Recommended for demos — feeds Kafka directly.",
                 bg=PANEL, fg=INK_FAINT, font=("Segoe UI", 8)).pack(
            anchor="w", pady=(3, 0))

        tk.Frame(pad, bg=STROKE, height=1).pack(fill="x", pady=10)
        tk.Label(pad, text="LIVE ATTACKS  (need the capture bridge below)",
                 bg=PANEL, fg=INK_DIM, font=("Segoe UI Semibold", 8)).pack(anchor="w")

        tgt = tk.Frame(pad, bg=PANEL)
        tgt.pack(fill="x", pady=(6, 8))
        tk.Label(tgt, text="Target IP", bg=PANEL, fg=INK_DIM, font=self.f_small).pack(
            side="left")
        self._entry(tgt, self.target_var, 16).pack(side="left", padx=(8, 0))

        grid = tk.Frame(pad, bg=PANEL)
        grid.pack(fill="x")
        for i, (label, key) in enumerate(ATTACKS):
            FlatButton(grid, label, command=lambda k=key: self.on_attack(k),
                       small=True).grid(row=i // 2, column=i % 2, sticky="ew",
                                        padx=(0 if i % 2 == 0 else 4,
                                              4 if i % 2 == 0 else 0), pady=3)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        FlatButton(pad, "Run ALL 6 Attacks", command=lambda: self.on_attack(None),
                   icon="⚔").pack(fill="x", pady=(6, 0))

        tk.Label(pad, text=("ⓘ Live attacks only put packets on the wire. They reach the "
                            "pipeline\nONLY via the capture bridge (sniffer). Needs Admin + "
                            "a reachable target.\nFor a guaranteed demo, use Inject Synthetic "
                            "Threats above."),
                 bg=PANEL, fg=AMBER, font=("Segoe UI", 8), justify="left").pack(
            anchor="w", pady=(10, 8))

        cap = tk.Frame(pad, bg=PANEL)
        cap.pack(fill="x")
        tk.Label(cap, text="Interface", bg=PANEL, fg=INK_DIM, font=self.f_small).pack(
            side="left")
        self._entry(cap, self.iface_var, 12).pack(side="left", padx=(8, 6))
        FlatButton(cap, "Start Capture Bridge", self.on_start_capture,
                   small=True, icon="📡").pack(side="left")

    def _entry(self, parent, var, width):
        wrap = tk.Frame(parent, bg=STROKE_HI)
        e = tk.Entry(wrap, textvariable=var, bg=BG, fg=INK, insertbackground=ACCENT,
                     relief="flat", width=width, font=self.f_body)
        e.pack(padx=1, pady=1, ipady=3, ipadx=4)
        return wrap

    def _build_log_panel(self, parent):
        outer, panel = self._card(parent)
        outer.pack(fill="both", expand=True)
        top = tk.Frame(panel, bg=PANEL)
        top.pack(fill="x", padx=14, pady=(12, 6))
        tk.Frame(top, bg=GREEN, width=3, height=14).pack(side="left", padx=(0, 8))
        tk.Label(top, text="CONSOLE", bg=PANEL, fg=INK,
                 font=("Segoe UI Semibold", 10)).pack(side="left")
        FlatButton(top, "Clear", self._clear_log, kind="ghost", small=True).pack(
            side="right")

        text_wrap = tk.Frame(panel, bg=STROKE)
        text_wrap.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.log_text = tk.Text(text_wrap, bg="#070a10", fg=INK, insertbackground=INK,
                                relief="flat", wrap="word", font=self.f_mono,
                                padx=12, pady=10, borderwidth=0)
        self.log_text.pack(fill="both", expand=True, padx=1, pady=1)
        self.log_text.tag_configure("cmd", foreground=ACCENT)
        self.log_text.tag_configure("ok", foreground=GREEN)
        self.log_text.tag_configure("err", foreground=RED)
        self.log_text.configure(state="disabled")
        self._log_line(f"UniGuard v{APP_VERSION} — Offline Control Console")
        self._log_line(f"Project root: {ROOT}")
        self._log_line("Ready. Click Start Pipeline to launch the stack.")

    def _log_line(self, text):
        tag = None
        if text.startswith("$"):
            tag = "cmd"
        elif text.startswith("[ok]"):
            tag = "ok"
        elif text.startswith("[error]") or text.startswith("[exit"):
            tag = "err"
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", tag or ())
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _drain_log(self):
        try:
            while True:
                self._log_line(self.log_queue.get_nowait())
        except queue.Empty:
            pass
        self.after(120, self._drain_log)

    # ==================================================================
    # DASHBOARD VIEW
    # ==================================================================
    def _build_dashboard_view(self, parent):
        wrap = tk.Frame(parent, bg=BG)
        wrap.pack(fill="both", expand=True, padx=18, pady=16)

        # stat cards row
        cards = tk.Frame(wrap, bg=BG)
        cards.pack(fill="x")
        self.card_widgets = {}
        specs = [("TOTAL ALERTS", "total", ACCENT), ("ALERTS / MIN", "rate", GREEN),
                 ("CRITICAL", "critical", RED), ("ACTIVE SOURCES", "sources", PURPLE)]
        for i, (title, key, color) in enumerate(specs):
            self._stat_card(cards, title, key, color, i)
            cards.columnconfigure(i, weight=1)

        # charts row: donut + line chart
        charts = tk.Frame(wrap, bg=BG)
        charts.pack(fill="x", pady=(14, 0))
        charts.columnconfigure(0, weight=1, minsize=380)
        charts.columnconfigure(1, weight=1)

        d_outer, d_panel = self._card(charts, "THREAT DISTRIBUTION")
        d_outer.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        self.donut = tk.Canvas(d_panel, bg=PANEL, highlightthickness=0, height=210)
        self.donut.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        l_outer, l_panel = self._card(charts, "ALERT RATE  (last ~2 min)")
        l_outer.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        self.line = tk.Canvas(l_panel, bg=PANEL, highlightthickness=0, height=210)
        self.line.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        # bars row: severity + top sources
        bars = tk.Frame(wrap, bg=BG)
        bars.pack(fill="x", pady=(14, 0))
        bars.columnconfigure(0, weight=1)
        bars.columnconfigure(1, weight=1)
        s_outer, s_panel = self._card(bars, "SEVERITY")
        s_outer.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        self.severity_box = tk.Frame(s_panel, bg=PANEL, height=130)
        self.severity_box.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self.severity_box.pack_propagate(False)
        src_outer, src_panel = self._card(bars, "TOP SOURCES")
        src_outer.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        self.sources_box = tk.Frame(src_panel, bg=PANEL, height=130)
        self.sources_box.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self.sources_box.pack_propagate(False)

        # live feed
        f_outer, f_panel = self._card(wrap)
        f_outer.pack(fill="both", expand=True, pady=(14, 0))
        head = tk.Frame(f_panel, bg=PANEL)
        head.pack(fill="x", padx=14, pady=(12, 6))
        tk.Frame(head, bg=RED, width=3, height=14).pack(side="left", padx=(0, 8))
        tk.Label(head, text="LIVE ALERT FEED", bg=PANEL, fg=INK,
                 font=("Segoe UI Semibold", 10)).pack(side="left")
        self.feed_status = tk.Label(head, text="waiting for backend...", bg=PANEL,
                                    fg=INK_DIM, font=self.f_small)
        self.feed_status.pack(side="right")
        feed_wrap = tk.Frame(f_panel, bg=STROKE)
        feed_wrap.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.feed = tk.Text(feed_wrap, bg="#070a10", fg=INK, relief="flat",
                            wrap="none", font=self.f_mono, padx=12, pady=8,
                            borderwidth=0)
        self.feed.pack(fill="both", expand=True, padx=1, pady=1)
        for sev, color in SEVERITY_COLORS.items():
            self.feed.tag_configure(sev, foreground=color)
        self.feed.tag_configure("dim", foreground=INK_FAINT)
        self.feed.configure(state="disabled")

    def _stat_card(self, parent, title, key, color, col):
        outer = tk.Frame(parent, bg=STROKE)
        outer.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 7, 0))
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Frame(inner, bg=color, height=3).pack(fill="x")
        body = tk.Frame(inner, bg=PANEL)
        body.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(body, text=title, bg=PANEL, fg=INK_DIM,
                 font=("Segoe UI Semibold", 9)).pack(anchor="w")
        val = tk.Label(body, textvariable=self.card_vars[key], bg=PANEL, fg=color,
                       font=("Segoe UI", 30, "bold"))
        val.pack(anchor="w", pady=(2, 0))
        self.card_widgets[key] = val

    def _animate_cards(self):
        for key, target in self.card_targets.items():
            cur = self.card_display[key]
            if abs(cur - target) > 0.5:
                cur += (target - cur) * 0.25
                self.card_display[key] = cur
                if key == "rate":
                    self.card_vars[key].set(f"{target:.1f}")
                else:
                    self.card_vars[key].set(str(int(round(cur))))
            else:
                self.card_display[key] = float(target)
                self.card_vars[key].set(f"{target:.1f}" if key == "rate"
                                        else str(int(target)))
        self.after(40, self._animate_cards)

    # ---- canvas charts ----
    def _draw_donut(self, items):
        c = self.donut
        c.delete("all")
        w = c.winfo_width() or 360
        h = c.winfo_height() or 210
        cx, cy = h // 2 + 8, h // 2
        r_out, r_in = min(cx, cy) - 14, (min(cx, cy) - 14) * 0.58
        total = sum(v for _, v in items)
        if total == 0:
            c.create_oval(cx - r_out, cy - r_out, cx + r_out, cy + r_out,
                          outline=STROKE, width=2)
            c.create_text(cx, cy, text="no data", fill=INK_FAINT,
                          font=("Segoe UI", 10))
            return
        start = 90.0
        for label, val in items:
            extent = -360.0 * (val / total)
            color = THREAT_COLORS.get(label, INK_FAINT)
            c.create_arc(cx - r_out, cy - r_out, cx + r_out, cy + r_out,
                         start=start, extent=extent, fill=color, outline=PANEL,
                         width=2, style="pieslice")
            start += extent
        c.create_oval(cx - r_in, cy - r_in, cx + r_in, cy + r_in, fill=PANEL,
                      outline=PANEL)
        c.create_text(cx, cy - 8, text=str(total), fill=INK,
                      font=("Segoe UI", 20, "bold"))
        c.create_text(cx, cy + 14, text="alerts", fill=INK_DIM, font=("Segoe UI", 9))
        # legend
        lx = cx + r_out + 24
        ly = 24
        for label, val in items:
            color = THREAT_COLORS.get(label, INK_FAINT)
            c.create_rectangle(lx, ly, lx + 11, ly + 11, fill=color, outline="")
            c.create_text(lx + 18, ly + 5, anchor="w",
                          text=f"{label}  {val}", fill=INK_DIM,
                          font=("Segoe UI", 9))
            ly += 22

    def _draw_line(self, series):
        c = self.line
        c.delete("all")
        w = c.winfo_width() or 400
        h = c.winfo_height() or 210
        pad_l, pad_r, pad_t, pad_b = 34, 12, 16, 22
        x0, y0, x1, y1 = pad_l, pad_t, w - pad_r, h - pad_b
        vals = list(series)
        vmax = max(vals + [1])
        # gridlines + y labels
        for i in range(4):
            gy = y0 + (y1 - y0) * i / 3
            c.create_line(x0, gy, x1, gy, fill=STROKE)
            c.create_text(x0 - 6, gy, anchor="e",
                          text=str(int(round(vmax * (1 - i / 3)))),
                          fill=INK_FAINT, font=("Segoe UI", 8))
        if len(vals) < 2:
            c.create_text((x0 + x1) / 2, (y0 + y1) / 2, text="collecting...",
                          fill=INK_FAINT, font=("Segoe UI", 10))
            return
        n = len(vals)
        pts = []
        for i, v in enumerate(vals):
            px = x0 + (x1 - x0) * i / (n - 1)
            py = y1 - (y1 - y0) * (v / vmax)
            pts.append((px, py))
        # area fill
        area = [x0, y1] + [coord for p in pts for coord in p] + [x1, y1]
        c.create_polygon(area, fill="#12233f", outline="")
        # line
        flat = [coord for p in pts for coord in p]
        c.create_line(flat, fill=ACCENT, width=2, smooth=True)
        for px, py in pts[-1:]:
            c.create_oval(px - 3, py - 3, px + 3, py + 3, fill=ACCENT, outline=PANEL)
        c.create_text(x1, y1 + 12, anchor="e", text="now", fill=INK_FAINT,
                      font=("Segoe UI", 8))

    def _render_bars(self, holder, items, color_map=None, default_color=ACCENT):
        for wdg in holder.winfo_children():
            wdg.destroy()
        if not items:
            tk.Label(holder, text="no data yet", bg=PANEL, fg=INK_FAINT,
                     font=self.f_small).pack(anchor="w", pady=8)
            return
        max_val = max(v for _, v in items) or 1
        for label, val in items:
            color = (color_map or {}).get(label, default_color)
            row = tk.Frame(holder, bg=PANEL)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=label, bg=PANEL, fg=INK, width=16, anchor="w",
                     font=self.f_small).pack(side="left")
            tk.Label(row, text=str(val), bg=PANEL, fg=INK_DIM, width=5, anchor="e",
                     font=self.f_small).pack(side="right")
            track = tk.Frame(row, bg=BG, height=12)
            track.pack(side="left", fill="x", expand=True, padx=8)
            track.pack_propagate(False)
            bar = tk.Frame(track, bg=color, height=12)
            bar.place(relwidth=max(0.03, val / max_val), relheight=1.0)

    # ==================================================================
    # ACTIONS
    # ==================================================================
    def on_start(self):
        self._log_line("Starting pipeline (docker compose up -d)...")
        self.runner.run_async(compose_command() + ["up", "-d"],
                              label="docker compose up -d")

    def on_rebuild(self):
        self._log_line("Rebuilding & starting pipeline...")
        self.runner.run_async(compose_command() + ["up", "-d", "--build"],
                              label="docker compose up -d --build")

    def on_stop(self):
        if not messagebox.askyesno("Stop Pipeline",
                                   "Stop and remove all pipeline containers?"):
            return
        self.runner.run_async(compose_command() + ["down"],
                              label="docker compose down")

    def on_clear(self):
        def work():
            ok = http_post(BACKEND_CLEAR_URL)
            self.log_queue.put("[ok] alerts cleared" if ok
                               else "[error] could not reach backend to clear alerts")
        threading.Thread(target=work, daemon=True).start()
        self.rate_series.clear()
        self._last_total = None

    def on_inject(self):
        script = ROOT / "scripts" / "inject_all_threats.py"
        if not script.exists():
            self._log_line(f"[error] not found: {script}")
            return
        self._log_line("Injecting synthetic threats -> switch to Dashboard to watch.")
        self.runner.run_async([self._python(), str(script)],
                              label="inject_all_threats.py")

    def on_attack(self, only_key):
        script = ROOT / "scripts" / "attack_metasploitable.py"
        if not script.exists():
            self._log_line(f"[error] not found: {script}")
            return
        self._log_line("[note] attacks need the capture bridge running to reach the "
                       "pipeline.")
        args = [self._python(), str(script), "--target", self.target_var.get().strip()]
        if only_key:
            args += ["--only", only_key]
        self.runner.run_async(args, label=f"attack {only_key or 'ALL-6'}")

    def on_start_capture(self):
        script = ROOT / "scripts" / "live_capture.py"
        if not script.exists():
            self._log_line(f"[error] not found: {script}")
            return
        iface = self.iface_var.get().strip()
        target = self.target_var.get().strip()
        self._log_line(f"Starting capture bridge on '{iface}' (needs Administrator).")
        self.runner.run_async(
            [self._python(), str(script), "--interface", iface, "--target", target],
            label=f"live_capture on {iface}")

    def on_open_terminal(self):
        """Open a PowerShell window in the project root (a normal, visible
        interactive terminal — separate from the in-app console)."""
        try:
            subprocess.Popen(
                ["cmd", "/c", "start", "powershell", "-NoExit",
                 "-Command", f"Set-Location -LiteralPath '{ROOT}'"],
                cwd=str(ROOT))
            self._log_line(f"Opened a terminal in {ROOT}")
        except Exception as exc:  # noqa: BLE001
            self._log_line(f"[error] could not open terminal: {exc}")

    def _python(self):
        return "python" if getattr(sys, "frozen", False) else sys.executable

    # ==================================================================
    # HEALTH MONITORING
    # ==================================================================
    def _start_health_thread(self):
        threading.Thread(target=self._health_loop, daemon=True).start()

    def _health_loop(self):
        while True:
            containers = docker_all_containers()
            health = http_get_json(BACKEND_HEALTH_URL)
            self.after(0, self._apply_health, containers, health)
            time.sleep(4)

    def _apply_health(self, containers, health):
        if containers is None:
            self.pipeline_state.set("DOCKER OFF")
            self.state_dot.configure(fg=RED)
            for dot, state in self.service_labels.values():
                dot.configure(fg=INK_FAINT)
                state.configure(text="docker not found")
            return
        server_up = server_total = 0
        for container, (dot, state) in self.service_labels.items():
            st = containers.get(container)
            is_batch = container == "ingest"
            if not is_batch:
                server_total += 1
            if st == "running":
                if not is_batch:
                    server_up += 1
                if container == "backend" and health:
                    dot.configure(fg=GREEN); state.configure(text="healthy")
                else:
                    dot.configure(fg=GREEN); state.configure(text="running")
            elif st in ("exited", "dead"):
                if is_batch:
                    dot.configure(fg=ACCENT); state.configure(text="completed")
                else:
                    dot.configure(fg=RED); state.configure(text="stopped")
            else:
                dot.configure(fg=INK_FAINT); state.configure(text="not created")
        if server_up == 0:
            self.pipeline_state.set("STOPPED"); self.state_dot.configure(fg=INK_FAINT)
        elif server_up < server_total:
            self.pipeline_state.set(f"PARTIAL {server_up}/{server_total}")
            self.state_dot.configure(fg=AMBER)
        else:
            self.pipeline_state.set("RUNNING"); self.state_dot.configure(fg=GREEN)

    # ==================================================================
    # DASHBOARD DATA
    # ==================================================================
    def _start_dashboard_thread(self):
        threading.Thread(target=self._dashboard_loop, daemon=True).start()

    def _dashboard_loop(self):
        while True:
            stats = http_get_json(BACKEND_STATS_URL)
            recent = http_get_json(BACKEND_RECENT_URL)
            self.after(0, self._apply_dashboard, stats, recent)
            time.sleep(3)

    def _apply_dashboard(self, stats, recent):
        if stats:
            total = stats.get("total_alerts", 0)
            self.card_targets["total"] = total
            self.card_targets["rate"] = stats.get("alerts_per_minute", 0)
            by_sev = stats.get("by_severity", {}) or {}
            self.card_targets["critical"] = by_sev.get("CRITICAL", 0)
            top_sources = stats.get("top_sources", {}) or {}
            self.card_targets["sources"] = len(top_sources)

            # rolling rate series (new alerts per 3s tick)
            if self._last_total is not None:
                self.rate_series.append(max(0, total - self._last_total))
            self._last_total = total

            by_threat = stats.get("by_threat_class", {}) or {}
            self._draw_donut(sorted(by_threat.items(), key=lambda x: x[1], reverse=True))
            self._draw_line(self.rate_series)
            sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            self._render_bars(self.severity_box,
                              [(s, by_sev[s]) for s in sev_order if s in by_sev],
                              color_map=SEVERITY_COLORS)
            self._render_bars(self.sources_box,
                              sorted(top_sources.items(), key=lambda x: x[1],
                                     reverse=True)[:5], default_color=PURPLE)

        if recent is not None:
            self._render_feed(recent.get("alerts", []))
            self.feed_status.configure(
                text=f"updated {datetime.now().strftime('%H:%M:%S')}", fg=GREEN)
        else:
            self.feed_status.configure(text="backend unreachable", fg=RED)

    def _render_feed(self, alerts):
        self.feed.configure(state="normal")
        self.feed.delete("1.0", "end")
        if not alerts:
            self.feed.insert("end", "No alerts yet. Inject synthetic threats, or run "
                                    "attacks with the capture bridge active.\n", "dim")
        for a in alerts:
            try:
                tstr = datetime.fromtimestamp(float(a.get("timestamp", 0))).strftime("%H:%M:%S")
            except (ValueError, OSError, OverflowError):
                tstr = "--:--:--"
            sev = a.get("severity", "UNKNOWN")
            line = (f"{tstr}  [{sev:<8}] {a.get('threat_class','?'):<16} "
                    f"{a.get('src_ip','?')}:{a.get('src_port',0)} -> "
                    f"{a.get('dst_ip','?')}:{a.get('dst_port',0)}  "
                    f"conf={a.get('confidence',0):.2f}\n")
            self.feed.insert("end", line, sev if sev in SEVERITY_COLORS else "dim")
        self.feed.configure(state="disabled")


def main():
    ThreatConsole().mainloop()


if __name__ == "__main__":
    main()
