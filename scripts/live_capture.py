"""
LIVE CAPTURE MODE - Sniffs network traffic in real-time and feeds to Kafka.

This script runs NATIVELY on Windows (not in Docker) because Docker
cannot access host network interfaces on Windows.

It captures traffic passively (read-only, unidirectional - simulating a data diode)
and sends packet records to Kafka for the ML pipeline to process.

Usage:
    python scripts/live_capture.py --interface "Wi-Fi"
    python scripts/live_capture.py --interface "Wi-Fi" --target 192.168.56.1

Requirements:
    pip install scapy confluent-kafka

Architecture:
    YOUR MACHINE (attacker tools: nmap, hping3)
         │
         │ malicious traffic
         ▼
    NETWORK (Wi-Fi / Ethernet)
         │
         │ passive copy (promiscuous mode sniffing)
         ▼
    THIS SCRIPT (data diode simulator)
         │
         │ ONE WAY → Kafka
         ▼
    DOCKER PIPELINE (Feature Extraction → ALL ML Models → Alert)
         │
         ▼
    DASHBOARD (http://localhost:3000)
"""

import argparse
import json
import sys
import time
import threading
from datetime import datetime
from collections import defaultdict

# Force UTF-8 output so Unicode characters never crash on a cp1252 console
# (e.g. when this script is launched as a subprocess by the desktop launcher).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, conf
except ImportError:
    print("ERROR: Install scapy: pip install scapy")
    sys.exit(1)

try:
    from confluent_kafka import Producer
except ImportError:
    print("ERROR: Install confluent-kafka: pip install confluent-kafka")
    sys.exit(1)


# ============================================================================
# Configuration
# ============================================================================

KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "flow-records"

# Stats tracking
stats = {
    "packets_captured": 0,
    "packets_sent": 0,
    "errors": 0,
    "start_time": time.time(),
    "by_protocol": defaultdict(int),
}


# ============================================================================
# Packet Processing
# ============================================================================

def extract_dns_query(pkt):
    """Extract DNS query name from packet, filtering out local/mDNS noise."""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            qname = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
            # Skip mDNS / local service discovery — these are NOT DGA
            if _is_local_dns(qname):
                return None
            return qname
        except (UnicodeDecodeError, AttributeError):
            return None
    return None


# Domains/suffixes that should never be flagged as DGA
_LOCAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
    ".intranet",
    ".corp",
    ".arpa",
)

# mDNS service prefixes (RFC 6763 service discovery)
_SERVICE_PREFIXES = (
    "_tcp.",
    "_udp.",
    "_http.",
    "_https.",
    "_spotify",
    "_companion",
    "_airplay",
    "_raop",
    "_smb.",
    "_afpovertcp.",
    "_ipp.",
    "_printer.",
    "_pdl-datastream.",
    "_sleep-proxy.",
    "_homekit.",
    "_hap.",
    "_matter.",
    "_googlecast.",
    "_chromecast.",
)

# Multicast/broadcast destination IPs
_MULTICAST_DNS_IPS = {"224.0.0.251", "ff02::fb", "224.0.0.252", "255.255.255.255"}

# All multicast/broadcast IPs that should be excluded from threat analysis
# These generate massive false positives on shared/public networks
_MULTICAST_BROADCAST_IPS = {
    "224.0.0.251",       # mDNS
    "224.0.0.252",       # LLMNR
    "239.255.255.250",   # SSDP / UPnP
    "224.0.0.1",         # All hosts
    "224.0.0.2",         # All routers
    "224.0.0.22",        # IGMP
    "224.0.0.251",       # mDNS
    "224.0.0.252",       # LLMNR
    "224.0.0.253",       # Teredo
    "255.255.255.255",   # Broadcast
    "ff02::1",           # IPv6 all nodes
    "ff02::fb",          # IPv6 mDNS
    "ff02::1:3",         # IPv6 LLMNR
}


def _is_local_dns(domain: str) -> bool:
    """Check if a domain is local/mDNS and should be excluded from DGA analysis."""
    dl = domain.lower()

    # .local, .arpa, etc.
    for suffix in _LOCAL_SUFFIXES:
        if dl.endswith(suffix):
            return True

    # Service discovery records (_tcp.local, _spotify-connect._tcp.local)
    for prefix in _SERVICE_PREFIXES:
        if prefix in dl:
            return True

    # Underscore-prefixed labels are almost always service records
    if dl.startswith("_"):
        return True

    return False


def _is_multicast_dst(pkt) -> bool:
    """Check if packet is destined to a multicast/broadcast address."""
    if pkt.haslayer(IP):
        return pkt[IP].dst in _MULTICAST_DNS_IPS
    return False


def packet_to_record(pkt):
    """Convert a scapy packet to our JSON flow record format."""
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]

    # Skip all multicast/broadcast traffic — these are local network noise,
    # not threats. Covers mDNS, SSDP/UPnP, IGMP, LLMNR, etc.
    dst = ip_layer.dst
    if (dst in _MULTICAST_BROADCAST_IPS
            or dst.startswith("224.")
            or dst.startswith("239.")
            or dst.startswith("ff02:")
            or dst == "255.255.255.255"):
        return None

    record = {
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": 0,
        "dst_port": 0,
        "protocol": ip_layer.proto,
        "timestamp_us": int(float(pkt.time) * 1_000_000),
        "packet_len": len(ip_layer),
        "payload_len": len(ip_layer.payload) if ip_layer.payload else 0,
        "tcp_flags": None,
        "dns_query": None,
        "ingest_time": datetime.utcnow().isoformat(),
    }

    # TCP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record["src_port"] = tcp.sport
        record["dst_port"] = tcp.dport
        record["tcp_flags"] = {
            "syn": bool(tcp.flags & 0x02),
            "ack": bool(tcp.flags & 0x10),
            "rst": bool(tcp.flags & 0x04),
            "fin": bool(tcp.flags & 0x01),
            "psh": bool(tcp.flags & 0x08),
            "urg": bool(tcp.flags & 0x20),
        }
        # Include raw TCP payload for TLS parsing (first 512 bytes max)
        raw_payload = bytes(tcp.payload) if tcp.payload else b""
        if raw_payload and len(raw_payload) > 0:
            import base64
            # Cap at 512 bytes — enough for Client/Server Hello
            record["payload_bytes_b64"] = base64.b64encode(raw_payload[:512]).decode("ascii")
        stats["by_protocol"]["TCP"] += 1

    # UDP
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        record["src_port"] = udp.sport
        record["dst_port"] = udp.dport
        stats["by_protocol"]["UDP"] += 1

    # DNS
    dns_query = extract_dns_query(pkt)
    if dns_query:
        record["dns_query"] = dns_query
        stats["by_protocol"]["DNS"] += 1

    return record


# ============================================================================
# Kafka Producer
# ============================================================================

class KafkaFeeder:
    def __init__(self, broker, topic):
        self.producer = Producer({
            "bootstrap.servers": broker,
            "queue.buffering.max.messages": 100000,
            "batch.num.messages": 500,
            "linger.ms": 10,
            "acks": "1",
        })
        self.topic = topic
        print(f"[+] Kafka producer connected to {broker}")
        print(f"[+] Producing to topic: {topic}")

    def send(self, record):
        """Send a packet record to Kafka."""
        try:
            key = f"{record['src_ip']}:{record['src_port']}-{record['dst_ip']}:{record['dst_port']}"
            payload = json.dumps(record)
            self.producer.produce(
                topic=self.topic,
                key=key.encode("utf-8"),
                value=payload.encode("utf-8"),
            )
            self.producer.poll(0)
            stats["packets_sent"] += 1
        except Exception as e:
            stats["errors"] += 1
            if stats["errors"] <= 5:
                print(f"[!] Kafka error: {e}")

    def flush(self):
        self.producer.flush(timeout=5)


# ============================================================================
# Stats Display
# ============================================================================

def print_stats_loop():
    """Print capture statistics every 5 seconds."""
    while True:
        time.sleep(5)
        elapsed = time.time() - stats["start_time"]
        rate = stats["packets_captured"] / elapsed if elapsed > 0 else 0
        print(
            f"\r[LIVE] Captured: {stats['packets_captured']} | "
            f"Sent to Kafka: {stats['packets_sent']} | "
            f"Rate: {rate:.0f} pkt/s | "
            f"TCP: {stats['by_protocol']['TCP']} "
            f"UDP: {stats['by_protocol']['UDP']} "
            f"DNS: {stats['by_protocol']['DNS']} | "
            f"Errors: {stats['errors']}",
            end="", flush=True,
        )


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Live network capture -> Kafka -> ML Pipeline -> Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Capture all traffic on Wi-Fi
  python scripts/live_capture.py --interface "Wi-Fi"

  # Capture only traffic to/from a specific target
  python scripts/live_capture.py --interface "Wi-Fi" --target 192.168.56.1

  # Then in another terminal, run attacks:
  nmap -sS 192.168.56.1          -> triggers PortScan detection
  hping3 -S --flood 192.168.56.1 -> triggers DDoS detection
  nslookup x8k2m9q.com           -> triggers DGA detection

DASHBOARD: http://localhost:3000
        """
    )
    parser.add_argument("--interface", "-i", required=True,
                        help="Network interface to capture on (e.g. 'Wi-Fi', 'Ethernet')")
    parser.add_argument("--target", "-t", default=None,
                        help="Only capture traffic to/from this IP (optional filter)")
    parser.add_argument("--kafka-broker", default=KAFKA_BROKER,
                        help=f"Kafka broker address (default: {KAFKA_BROKER})")
    parser.add_argument("--count", "-c", type=int, default=0,
                        help="Number of packets to capture (0=infinite)")

    args = parser.parse_args()

    print("=" * 60)
    print("  LIVE CAPTURE MODE - Cyber Threat Detection")
    print("  Passive, Unidirectional, Read-Only")
    print("=" * 60)
    print(f"  Interface : {args.interface}")
    print(f"  Filter    : {'all traffic' if not args.target else f'to/from {args.target}'}")
    print(f"  Kafka     : {args.kafka_broker}")
    print(f"  Dashboard : http://localhost:3000")
    print("=" * 60)
    print()

    # Build BPF filter
    bpf_filter = "ip"
    if args.target:
        # Capture traffic to/from the target AND all DNS (port 53) traffic.
        # DNS queries go to the resolver, not the target, so we must include
        # them explicitly for DGA detection to work.
        bpf_filter = f"host {args.target} or port 53"
    print(f"[+] BPF filter: {bpf_filter}")

    # Initialize Kafka
    kafka = KafkaFeeder(args.kafka_broker, KAFKA_TOPIC)

    # Start stats thread
    stats_thread = threading.Thread(target=print_stats_loop, daemon=True)
    stats_thread.start()

    # Packet callback
    def process_packet(pkt):
        stats["packets_captured"] += 1
        record = packet_to_record(pkt)
        if record:
            kafka.send(record)

    # Start capture
    print(f"[+] Starting capture on '{args.interface}'...")
    print(f"[+] Traffic flows: Network -> This Script -> Kafka -> ML Models -> Dashboard")
    print(f"[+] Press Ctrl+C to stop\n")

    try:
        sniff(
            iface=args.interface,
            prn=process_packet,
            filter=bpf_filter,
            store=False,
            count=args.count if args.count > 0 else 0,
        )
    except KeyboardInterrupt:
        print("\n\n[+] Stopping capture...")
    except PermissionError:
        print("\n[!] ERROR: Need admin privileges to capture packets.")
        print("    Run this script as Administrator (right-click -> Run as Administrator)")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Capture error: {e}")
        print("    Make sure Npcap is installed: https://npcap.com/")
        sys.exit(1)
    finally:
        kafka.flush()
        elapsed = time.time() - stats["start_time"]
        print(f"\n[+] Capture complete:")
        print(f"    Duration: {elapsed:.1f}s")
        print(f"    Packets captured: {stats['packets_captured']}")
        print(f"    Packets sent to Kafka: {stats['packets_sent']}")
        print(f"    Avg rate: {stats['packets_captured']/elapsed:.0f} pkt/s")


if __name__ == "__main__":
    main()
