"""
Live attack demo against Metasploitable 2 (192.168.56.101).

Runs REAL attacks from your Windows host so the live_capture sniffer picks up
genuine traffic and the ML pipeline generates alerts on the dashboard.

Run this AS ADMINISTRATOR while live_capture.py is sniffing "Ethernet 2".

Attacks (each mapped to a detector):
  1. Port Scan          -> nmap SYN scan across many ports
  2. DDoS               -> high-rate SYN flood to port 80
  3. Data Exfil         -> bulk upload (large data push) to an open port
  4. C2 Beaconing       -> periodic regular connections to a backdoor port
  5. Encrypted Malware  -> repeated encrypted-looking sessions on a non-std port
  6. DGA                -> DNS queries for random-looking domains

Usage:
  python scripts/attack_metasploitable.py                 # run all six
  python scripts/attack_metasploitable.py --only portscan # run one
  python scripts/attack_metasploitable.py --only encmal
  python scripts/attack_metasploitable.py --target 192.168.56.101
"""

import argparse
import random
import socket
import string
import subprocess
import sys
import time

TARGET = "192.168.56.101"


def banner(step, name, detail):
    print("\n" + "=" * 60)
    print(f"[{step}] {name}")
    print(f"    {detail}")
    print("=" * 60)


def attack_portscan(target):
    banner("1/5", "PORT SCAN", f"nmap SYN scan of {target} ports 1-1000")
    try:
        subprocess.run(
            ["nmap", "-sS", "-T4", "-p", "1-1000", target],
            timeout=120,
        )
    except FileNotFoundError:
        print("    [!] nmap not found. Install from nmap.org")
    except subprocess.TimeoutExpired:
        print("    [*] scan running long, moving on")
    print("    -> Expect: PortScan alert")


def attack_ddos(target, duration=12):
    banner("2/5", "DDoS SYN FLOOD", f"High-rate traffic to {target}:80 for {duration}s")
    # Generate sustained high packet-rate traffic on ONE flow (same src port reused
    # via HTTP requests to the open web server on port 80). Metasploitable's Apache
    # will respond, creating a high-volume bidirectional flow.
    import threading

    def flood_worker():
        end = time.time() + duration
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((target, 80))
                # Send rapid HTTP requests to generate many packets fast
                for _ in range(50):
                    try:
                        s.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                        s.recv(512)
                    except Exception:
                        break
                s.close()
            except Exception:
                pass

    print(f"    Flooding {target}:80 with {8} parallel workers ...")
    threads = [threading.Thread(target=flood_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("    -> Expect: DDoS alert (high packet rate)")


def attack_exfiltration(target, mb=8):
    banner("3/5", "DATA EXFILTRATION", f"Bulk upload of ~{mb}MB to {target} (heavy outbound)")
    # Push a large volume of outbound data on a SINGLE sustained flow.
    # We target open ports and keep the socket alive by sending in a tight loop.
    # Metasploitable services (telnet:23, ssh:22) hold the connection long enough
    # to accumulate a big asymmetric upload before they drop it.
    for port in (23, 22, 21, 80):
        print(f"    Trying bulk upload to {target}:{port} ...")
        payload = b"X" * 1400
        total = 0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            target_bytes = mb * 1024 * 1024
            t_end = time.time() + 15
            while total < target_bytes and time.time() < t_end:
                try:
                    sent = s.send(payload)
                    total += sent
                except Exception:
                    break
            s.close()
        except Exception as e:
            print(f"    [*] {port} ended: {e}")
        if total > 100000:
            print(f"    Uploaded ~{total // 1024} KB outbound to :{port}")
            print("    -> Expect: DataExfiltration alert (asymmetric upload)")
            return
    print(f"    Uploaded ~{total // 1024} KB (may be below threshold)")
    print("    -> Expect: DataExfiltration alert (asymmetric upload)")


def attack_c2_beacon(target, port=1524, beacons=24, interval=1.5):
    # Port 1524 (ingreslock) is OPEN on Metasploitable — a classic backdoor port.
    # Each beacon opens a SEPARATE connection at a REGULAR interval. This creates
    # the periodic repeated-connection pattern that the C2 beacon detector catches.
    #
    # LIVE-ACCURACY: the C2 detector rejects a beacon if the interval jitter
    # (coefficient of variation) is too high. A naive `time.sleep(interval)` drifts
    # because the connect()/send() work itself takes variable time. We schedule each
    # beacon against an absolute timeline and use a SHORT connect timeout so a slow/
    # failed connect can't blow the interval budget. This keeps on-wire spacing tight.
    banner("4/6", "C2 BEACONING",
           f"{beacons} regular beacons to {target}:{port} every {interval}s (separate connections)")
    print(f"    Beaconing to {target}:{port} - one connection per beacon ...")
    start = time.time()
    for i in range(beacons):
        # Absolute scheduled time for THIS beacon — removes cumulative drift.
        scheduled = start + i * interval
        now = time.time()
        if scheduled > now:
            time.sleep(scheduled - now)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Short timeout: a hung connect must not eat into the next interval.
            s.settimeout(0.4)
            try:
                s.connect((target, port))
                # Small, consistent-size beacon payload
                s.send(b"BEACON_CHECKIN_" + bytes([65 + (i % 26)]) * 40)
                try:
                    s.recv(256)
                except Exception:
                    pass
            except Exception:
                # Even a failed connect generates the regular-interval SYN pattern
                pass
            s.close()
        except Exception:
            pass
        print(f"    beacon {i + 1}/{beacons}")
    print("    -> Expect: C2_BEACONING alert (periodic, low jitter)")


def attack_encrypted_malware(target, port=4444, sessions=14, interval=2.0):
    """Encrypted-malware-style flows: repeated sessions on a non-standard port
    with small, uniform, encrypted-looking payloads and near-symmetric exchange.

    Metasploitable exposes several non-standard service ports; 4444 (Metasploit
    default) / 6667 (IRC) / 8180 (Tomcat) are good candidates. Each session pushes
    a handful of fixed-size 'ciphertext-like' blobs, which the flow-metadata model
    scores as EncryptedMalware without any payload decryption.
    """
    banner("5/6", "ENCRYPTED MALWARE",
           f"{sessions} encrypted-looking sessions to {target} on a non-std port")
    ports = (port, 6667, 8180, 1524)
    blob = bytes((37 + (j * 7) % 200) for j in range(180))  # high-entropy-looking
    chosen = None
    for p in ports:
        opened = 0
        for i in range(sessions):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.6)
                s.connect((target, p))
                for _ in range(6):
                    s.send(blob)
                    try:
                        s.recv(128)
                    except Exception:
                        pass
                s.close()
                opened += 1
            except Exception:
                s.close() if 's' in dir() else None
            time.sleep(interval / 2 if i % 2 == 0 else interval)
        if opened > 0:
            chosen = p
            print(f"    Completed {opened}/{sessions} sessions on :{p}")
            break
    if chosen is None:
        print("    [*] No non-standard port accepted connections (target may be down)")
    print("    -> Expect: EncryptedMalware alert (non-std-port flow metadata)")


def _dns_query_udp(domain, resolver="8.8.8.8"):
    """Send a raw DNS A-record query over UDP port 53 (standard, sniffable)."""
    # Build a minimal DNS query packet
    tid = random.randint(0, 0xFFFF)
    header = tid.to_bytes(2, "big") + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    q = b""
    for label in domain.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + b"\x00\x01" + b"\x00\x01"  # type A, class IN
    packet = header + q
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.sendto(packet, (resolver, 53))
        try:
            s.recvfrom(512)
        except Exception:
            pass
        s.close()
    except Exception:
        pass


def attack_dga(count=12, resolver=None):
    banner("6/6", "DGA / DNS TUNNELING", f"{count} DNS queries for random domains")
    # Send raw UDP DNS queries on port 53 to the TARGET's DNS server so the
    # traffic crosses the sniffed host-only interface (Ethernet 2). Metasploitable
    # runs a DNS server on port 53. This guarantees the queries are captured.
    if resolver is None:
        resolver = TARGET  # query Metasploitable's DNS (crosses Ethernet 2)
    tlds = [".com", ".net", ".org", ".info", ".biz", ".xyz", ".top"]
    for i in range(count):
        length = random.randint(12, 22)
        domain = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
        domain += random.choice(tlds)
        _dns_query_udp(domain, resolver=resolver)
        print(f"    query: {domain}  (-> {resolver}:53)")
        time.sleep(0.3)
    print("    -> Expect: DGA alerts")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=TARGET, help="Metasploitable IP")
    ap.add_argument("--only",
                    choices=["portscan", "ddos", "exfil", "c2", "encmal", "dga"],
                    help="Run only one attack")
    args = ap.parse_args()
    t = args.target

    print("#" * 60)
    print("#  LIVE ATTACK DEMO - Metasploitable 2")
    print(f"#  Target: {t}")
    print("#  Make sure live_capture.py is running on 'Ethernet 2'")
    print("#" * 60)

    attacks = {
        "portscan": lambda: attack_portscan(t),
        "ddos": lambda: attack_ddos(t),
        "exfil": lambda: attack_exfiltration(t),
        "c2": lambda: attack_c2_beacon(t),
        "encmal": lambda: attack_encrypted_malware(t),
        "dga": lambda: attack_dga(resolver=t),
    }

    if args.only:
        attacks[args.only]()
    else:
        # Run all six in sequence with pauses so each shows up in its own window
        attack_portscan(t)
        time.sleep(3)
        attack_ddos(t)
        time.sleep(3)
        attack_exfiltration(t)
        time.sleep(3)
        attack_c2_beacon(t)
        time.sleep(3)
        attack_encrypted_malware(t)
        time.sleep(3)
        attack_dga(resolver=t)

    print("\n" + "#" * 60)
    print("#  ATTACKS COMPLETE")
    print("#  Check dashboard: http://localhost:3000")
    print("#  Alerts appear within ~10-15s (one detection window)")
    print("#" * 60)


if __name__ == "__main__":
    main()
