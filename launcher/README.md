# Threat Detection Console (`.exe`)

A native Windows desktop app that acts as a **one-click control panel** for the
whole SIH threat-detection pipeline. Instead of juggling several terminals, you
get a single window to start the stack, watch service health, open the SOC
dashboard, and fire off demo / live-attack scenarios.

> **What it is (and isn't):** the pipeline is a distributed system — Kafka, a
> Rust ingest service, Python ML services, a FastAPI backend, and a React
> dashboard, all orchestrated by Docker Compose. Those cannot be fused into one
> native binary. This `.exe` is a **launcher / operator console** that drives
> the existing Docker stack and helper scripts. It makes the project convenient
> and demo-ready without changing the architecture.

## Two views (switch from the top nav bar)

**Control Panel** and **Dashboard** — click either name in the top bar to switch.

### Control Panel

| Panel | Buttons / Info |
|---|---|
| **Pipeline Control** | Start (`docker compose up -d`), Stop (`down`), Rebuild (`up -d --build`), Open in Browser, Clear Alerts |
| **Service Health** | Live status dots for Kafka, ML Inference, Feature Extractor, Backend, Dashboard, Ingest (polled every 4s). Ingest is a batch job — it shows **completed** after replaying the PCAPs, which is normal, not an error. |
| **Demo & Attacks** | Inject synthetic threats (no VM/sniffer needed), plus per-threat live attacks and a capture-bridge starter |
| **Console** | Streams the output of every command it runs |

### Dashboard (embedded native SOC view)

Auto-refreshes every 3s from the backend REST API — no browser needed:
- **Stat cards**: total alerts, alerts/min, critical count, active sources
- **Threat distribution**, **severity breakdown**, **top sources** (bar charts)
- **Live alert feed**: most recent alerts, color-coded by severity

The **Open in Browser** button still opens the full React dashboard at
`http://localhost:3000` if you want the richer web UI.

## Why don't my live attacks show up on the dashboard?

This is the most common confusion, so it's worth being precise:

- **`Inject Synthetic Threats`** produces records *directly into Kafka*. It always
  works with no VM, no sniffer, and no admin rights. **Use this for demos.**
- **Live attacks** (Port Scan / DDoS / Exfil / C2 / DGA buttons) only put *real
  packets on the wire* aimed at a target IP. They reach the detection pipeline
  **only if the capture bridge is running** — i.e. `live_capture.py` is sniffing
  the interface and forwarding packets into Kafka.

So for live attacks to appear, you need **all** of:
1. The **capture bridge** running (use the *Start Capture Bridge* button, or run
   `python scripts/live_capture.py --interface "<name>" --target <ip>` **as
   Administrator** — packet capture needs Npcap + elevation).
2. A **reachable target** generating the traffic (e.g. Metasploitable 2 at
   `192.168.56.101` on a host-only network).
3. The **correct interface name** — run `python scripts/list_interfaces.py` to
   find the exact name scapy expects.

If any of those is missing, the packets never enter the pipeline and no alerts
appear — even though the attack itself "ran". The pipeline is fine; the capture
bridge is the missing link.

## Using the prebuilt `.exe`

1. Build it once (see below) — output lands at `launcher/dist/ThreatDetectionConsole.exe`.
2. Double-click it. The app finds the project by searching upward for
   `docker-compose.yml`, so keep it inside the repo (any subfolder works), or
   copy it next to `docker-compose.yml`.
3. Click **Start Pipeline**. Wait for the health dots to turn green.
4. Click **Open Dashboard**, then **Inject Synthetic Threats** to see alerts
   appear within ~10–15 seconds.

### Requirements at runtime
- **Docker Desktop** installed and running (the app calls `docker compose`).
- **Python** on `PATH` — only needed if you use the Inject / Attack buttons,
  since those run the repo's `scripts/*.py`. Starting/stopping the pipeline and
  opening the dashboard do **not** need Python.
- For live attacks: `nmap` and admin privileges, as described in the main README.

## Building the `.exe`

From the repo root (or the `launcher/` folder):

```powershell
powershell -ExecutionPolicy Bypass -File launcher/build.ps1
```

This regenerates the icon, installs PyInstaller if needed, and produces a
single-file, no-console executable at `launcher/dist/ThreatDetectionConsole.exe`.

### Manual build
```powershell
pip install pyinstaller
python launcher/make_icon.py         # (re)generate the icon
pyinstaller launcher/app.spec        # run from the launcher/ folder
```

## Run from source (no build)

```powershell
python launcher/app.py
```

The launcher uses only the Python standard library (`tkinter`, `urllib`,
`subprocess`, `threading`), so nothing extra is needed to run it directly.

## Files

| File | Purpose |
|---|---|
| `app.py` | The GUI application |
| `make_icon.py` | Generates `assets/app.ico` (stdlib only, no Pillow) |
| `app.spec` | PyInstaller build recipe (single file, windowed) |
| `build.ps1` | One-command build script |
| `version_info.txt` | Windows version/metadata embedded in the exe |
| `requirements.txt` | Build-time dependency (PyInstaller only) |
| `assets/app.ico` | Application icon |

## Endpoints the app talks to

- Dashboard: `http://localhost:3000`
- Backend health / stats: `http://localhost:8001/api/health`, `/api/stats`
- Clear alerts: `POST http://localhost:8001/api/alerts/clear`

These match `docker-compose.yml` (backend is published on host port **8001**).

## Notes

- The app never writes to the monitored network; it only orchestrates local
  Docker services and runs the repo's existing scripts. This preserves the
  project's read-only / passive design.
- Windows SmartScreen may warn on first launch because the exe is unsigned.
  Choose *More info → Run anyway*, or code-sign it for distribution.
