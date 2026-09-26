export function Footer({ uptime }: { uptime: string }) {
  const year = new Date().getFullYear()
  const githubUrl = 'https://github.com/swarnimbandekar/uniguard/releases/latest'
  return (
    <footer className="gov-footer">
      <div className="foot-main">
        <div className="foot-col">
          <div className="foot-h">About this system</div>
          <p>
            A read-only monitoring system that watches network traffic metadata and
            flags six classes of cyber threat in real time. It never decrypts payloads
            and never sends data back onto the network.
          </p>
        </div>
        <div className="foot-col">
          <div className="foot-h">Safeguards</div>
          <ul>
            <li>Monitoring only — no interference with live traffic</li>
            <li>Metadata analysis — payloads are never opened</li>
            <li>On-premises inference — nothing leaves the enclave</li>
          </ul>
        </div>
        <div className="foot-col">
          <div className="foot-h">Status</div>
          <ul className="mono">
            <li>Detection window · 10 seconds</li>
            <li>System uptime · {uptime}</li>
            <li>Detection models · 6 active</li>
          </ul>
        </div>
        <div className="foot-col">
          <div className="foot-h">Offline version</div>
          <p style={{ marginBottom: '10px' }}>
            Run UniGuard on your own machine without a browser. A native Windows
            desktop app with a built-in SOC dashboard and one-click pipeline control.
          </p>
          <a
            href={githubUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="foot-download"
          >
            ⬇ UniGuard Desktop (Windows .exe)
          </a>
          <div className="foot-download-sub">
            Python · Docker Desktop required
          </div>
        </div>
      </div>
      <div className="foot-bar">
        <span>© {year} National Technical Research Organisation, Government of India</span>
        <span>Built for Smart India Hackathon 2026 · सत्यमेव जयते</span>
      </div>
    </footer>
  )
}
