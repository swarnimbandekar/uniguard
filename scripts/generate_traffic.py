"""
Traffic Generation Script for Demo.
Generates synthetic PCAP files with realistic benign traffic and injected attacks:
- DDoS (SYN flood from spoofed sources)
- PortScan (sequential port probes)
- DGA/DNS Tunneling (random domain queries)

Requires: scapy (pip install scapy)
"""

import random
import sys
import time
import argparse
from pathlib import Path

try:
    from scapy.all import (
        Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap, RandIP, RandShort
    )
except ImportError:
    print("ERROR: Scapy is required. Install it with: pip install scapy")
    sys.exit(1)


def generate_benign_traffic(num_packets=1000, base_time=None):
    """Generate realistic benign traffic (web browsing, DNS, HTTPS)."""
    packets = []
    t = base_time or time.time()
    
    # Simulate a small LAN
    internal_ips = [f"192.168.1.{i}" for i in range(10, 30)]
    external_ips = [f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)]
    dns_server = "8.8.8.8"
    
    legit_domains = [
        "google.com", "facebook.com", "amazon.com", "github.com",
        "stackoverflow.com", "wikipedia.org", "reddit.com", "youtube.com",
        "twitter.com", "linkedin.com", "microsoft.com", "apple.com",
        "netflix.com", "cloudflare.com", "mozilla.org", "python.org",
    ]
    
    for i in range(num_packets):
        src_ip = random.choice(internal_ips)
        t += random.uniform(0.001, 0.1)  # Normal IAT
        
        pkt_type = random.choices(
            ["dns", "https", "http", "other"],
            weights=[0.2, 0.5, 0.2, 0.1]
        )[0]
        
        if pkt_type == "dns":
            domain = random.choice(legit_domains)
            pkt = (
                Ether() /
                IP(src=src_ip, dst=dns_server) /
                UDP(sport=random.randint(1024, 65535), dport=53) /
                DNS(rd=1, qd=DNSQR(qname=domain))
            )
        elif pkt_type == "https":
            dst_ip = random.choice(external_ips)
            flags = random.choice(["S", "SA", "A", "PA", "FA"])
            pkt = (
                Ether() /
                IP(src=src_ip, dst=dst_ip) /
                TCP(sport=random.randint(1024, 65535), dport=443, flags=flags) /
                Raw(load=b"\x00" * random.randint(50, 1400))
            )
        elif pkt_type == "http":
            dst_ip = random.choice(external_ips)
            flags = random.choice(["S", "SA", "A", "PA", "FA"])
            pkt = (
                Ether() /
                IP(src=src_ip, dst=dst_ip) /
                TCP(sport=random.randint(1024, 65535), dport=80, flags=flags) /
                Raw(load=b"\x00" * random.randint(100, 1200))
            )
        else:
            dst_ip = random.choice(external_ips)
            pkt = (
                Ether() /
                IP(src=src_ip, dst=dst_ip) /
                UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535)) /
                Raw(load=b"\x00" * random.randint(20, 200))
            )
        
        pkt.time = t
        packets.append(pkt)
    
    return packets, t


def generate_ddos_attack(num_packets=5000, target_ip="10.0.0.1", base_time=None):
    """Generate DDoS SYN flood from spoofed sources."""
    packets = []
    t = base_time or time.time()
    
    target_port = 80
    
    for i in range(num_packets):
        # Spoofed source IPs (randomized)
        src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        t += random.uniform(0.00001, 0.001)  # Very high rate
        
        pkt = (
            Ether() /
            IP(src=src_ip, dst=target_ip) /
            TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S", 
                seq=random.randint(0, 2**32-1))
        )
        pkt.time = t
        packets.append(pkt)
    
    return packets, t


def generate_port_scan(target_ip="192.168.1.100", scanner_ip="10.10.10.10", 
                       num_ports=500, base_time=None):
    """Generate port scan traffic (sequential port probing)."""
    packets = []
    t = base_time or time.time()
    
    # Scan ports 1-num_ports
    ports = list(range(1, num_ports + 1))
    random.shuffle(ports)  # Randomize order slightly
    
    for port in ports:
        t += random.uniform(0.001, 0.01)  # Scanner rate
        
        # SYN probe
        pkt = (
            Ether() /
            IP(src=scanner_ip, dst=target_ip) /
            TCP(sport=random.randint(40000, 60000), dport=port, flags="S",
                seq=random.randint(0, 2**32-1))
        )
        pkt.time = t
        packets.append(pkt)
        
        # Most ports respond with RST (closed)
        if random.random() < 0.95:
            t += random.uniform(0.0001, 0.001)
            rst_pkt = (
                Ether() /
                IP(src=target_ip, dst=scanner_ip) /
                TCP(sport=port, dport=pkt[TCP].sport, flags="RA")
            )
            rst_pkt.time = t
            packets.append(rst_pkt)
    
    return packets, t


def generate_dga_traffic(num_queries=200, src_ip="192.168.1.50", 
                         dns_server="8.8.8.8", base_time=None):
    """Generate DGA-like DNS queries (random domain names)."""
    packets = []
    t = base_time or time.time()
    
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    tlds = [".com", ".net", ".org", ".info", ".biz", ".xyz", ".top"]
    
    for i in range(num_queries):
        t += random.uniform(0.1, 2.0)  # DGA query interval
        
        # Generate random domain (DGA-style)
        length = random.randint(10, 24)
        domain = "".join(random.choices(chars, k=length)) + random.choice(tlds)
        
        pkt = (
            Ether() /
            IP(src=src_ip, dst=dns_server) /
            UDP(sport=random.randint(1024, 65535), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain))
        )
        pkt.time = t
        packets.append(pkt)
    
    return packets, t


def generate_demo_scenario(output_dir: str):
    """Generate a complete demo scenario with attack phases."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("DEMO TRAFFIC GENERATION")
    print("=" * 60)
    
    all_packets = []
    t = time.time()
    
    # Phase 1: Benign baseline (30 seconds worth)
    print("\n[Phase 1] Generating benign baseline traffic...")
    benign1, t = generate_benign_traffic(num_packets=2000, base_time=t)
    all_packets.extend(benign1)
    print(f"  Generated {len(benign1)} benign packets")
    
    # Phase 2: DDoS attack begins
    print("\n[Phase 2] Injecting DDoS SYN flood attack...")
    ddos_pkts, t = generate_ddos_attack(num_packets=5000, target_ip="10.0.0.1", base_time=t)
    # Mix some benign traffic during attack
    benign_during, _ = generate_benign_traffic(num_packets=500, base_time=t - 2)
    all_packets.extend(ddos_pkts)
    all_packets.extend(benign_during)
    print(f"  Generated {len(ddos_pkts)} DDoS packets + {len(benign_during)} background")
    
    # Phase 3: Brief calm + Port Scan
    print("\n[Phase 3] Injecting Port Scan attack...")
    t += 5  # 5 second gap
    benign2, t = generate_benign_traffic(num_packets=500, base_time=t)
    all_packets.extend(benign2)
    scan_pkts, t = generate_port_scan(target_ip="192.168.1.100", scanner_ip="10.10.10.10",
                                       num_ports=500, base_time=t)
    all_packets.extend(scan_pkts)
    print(f"  Generated {len(scan_pkts)} port scan packets")
    
    # Phase 4: DGA queries
    print("\n[Phase 4] Injecting DGA/DNS tunneling traffic...")
    t += 3  # 3 second gap
    dga_pkts, t = generate_dga_traffic(num_queries=300, src_ip="192.168.1.50", base_time=t)
    benign3, t2 = generate_benign_traffic(num_packets=300, base_time=t - 10)
    all_packets.extend(dga_pkts)
    all_packets.extend(benign3)
    print(f"  Generated {len(dga_pkts)} DGA DNS queries")
    
    # Phase 5: Return to normal
    print("\n[Phase 5] Generating recovery traffic (back to normal)...")
    t += 5
    benign_final, t = generate_benign_traffic(num_packets=1500, base_time=t)
    all_packets.extend(benign_final)
    print(f"  Generated {len(benign_final)} benign packets")
    
    # Sort all packets by timestamp
    all_packets.sort(key=lambda p: float(p.time))
    
    # Write to PCAP
    output_file = output_path / "demo_scenario.pcap"
    print(f"\n[Writing] Saving {len(all_packets)} packets to {output_file}")
    wrpcap(str(output_file), all_packets)
    
    # Also generate individual attack files for testing
    wrpcap(str(output_path / "benign_only.pcap"), benign1[:1000])
    wrpcap(str(output_path / "ddos_attack.pcap"), ddos_pkts[:2000])
    wrpcap(str(output_path / "portscan_attack.pcap"), scan_pkts)
    wrpcap(str(output_path / "dga_queries.pcap"), dga_pkts)
    
    print(f"\n{'='*60}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"  Total packets: {len(all_packets)}")
    print(f"  Duration: {all_packets[-1].time - all_packets[0].time:.1f} seconds")
    print(f"  Avg rate: {len(all_packets) / (all_packets[-1].time - all_packets[0].time):.0f} pkt/s")
    print(f"\nFiles generated:")
    print(f"  {output_path / 'demo_scenario.pcap'} (full demo)")
    print(f"  {output_path / 'benign_only.pcap'}")
    print(f"  {output_path / 'ddos_attack.pcap'}")
    print(f"  {output_path / 'portscan_attack.pcap'}")
    print(f"  {output_path / 'dga_queries.pcap'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate demo traffic for threat detection")
    parser.add_argument("--output", "-o", default="./data/pcaps", help="Output directory for PCAP files")
    parser.add_argument("--type", "-t", choices=["all", "benign", "ddos", "portscan", "dga"],
                        default="all", help="Type of traffic to generate")
    args = parser.parse_args()
    
    if args.type == "all":
        generate_demo_scenario(args.output)
    elif args.type == "benign":
        pkts, _ = generate_benign_traffic(num_packets=5000)
        wrpcap(f"{args.output}/benign.pcap", pkts)
        print(f"Generated {len(pkts)} benign packets")
    elif args.type == "ddos":
        pkts, _ = generate_ddos_attack(num_packets=10000)
        wrpcap(f"{args.output}/ddos.pcap", pkts)
        print(f"Generated {len(pkts)} DDoS packets")
    elif args.type == "portscan":
        pkts, _ = generate_port_scan(num_ports=1000)
        wrpcap(f"{args.output}/portscan.pcap", pkts)
        print(f"Generated {len(pkts)} port scan packets")
    elif args.type == "dga":
        pkts, _ = generate_dga_traffic(num_queries=500)
        wrpcap(f"{args.output}/dga.pcap", pkts)
        print(f"Generated {len(pkts)} DGA packets")
