"""
Inject synthetic test traffic to Kafka to verify end-to-end detection
without needing live capture or a target VM.

Threats tested:
  1. DDoS - SYN flood (high packet rate to one destination)
  2. DGA - suspicious algorithmically-generated domain queries
  3. Encrypted Malware / C2 - beaconing on a non-standard port
  4. Data Exfiltration - bulk upload with minimal server response

For live attacks against a real target VM, use attack_metasploitable.py instead.
"""

import json
import sys
import time

try:
    from confluent_kafka import Producer
except ImportError:
    print("ERROR: pip install confluent-kafka")
    sys.exit(1)

KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "flow-records"


def make_pkt(src_ip, dst_ip, src_port, dst_port, protocol=6,
             pkt_len=200, payload_len=100, tcp_flags=None, dns_query=None):
    """Create a packet record."""
    if tcp_flags is None:
        tcp_flags = {"syn": False, "ack": True, "rst": False, "fin": False, "psh": True, "urg": False}
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "timestamp_us": int(time.time() * 1_000_000),
        "packet_len": pkt_len,
        "payload_len": payload_len,
        "tcp_flags": tcp_flags,
        "dns_query": dns_query,
        "ingest_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def send(producer, pkt):
    key = f"{pkt['src_ip']}:{pkt['src_port']}-{pkt['dst_ip']}:{pkt['dst_port']}"
    producer.produce(KAFKA_TOPIC, key=key.encode(), value=json.dumps(pkt).encode())
    producer.poll(0)


def inject_ddos_syn_flood(producer):
    """Simulate SYN flood: 5000 SYN packets in 2 seconds."""
    print("\n[1/4] Injecting: DDoS SYN flood (5000 SYN packets)")
    src_ip = "10.99.99.99"
    dst_ip = "192.168.1.100"
    dst_port = 80

    syn_flags = {"syn": True, "ack": False, "rst": False, "fin": False, "psh": False, "urg": False}

    for i in range(5000):
        pkt = make_pkt(src_ip, dst_ip, 10000 + (i % 60000), dst_port,
                       pkt_len=60, payload_len=0, tcp_flags=syn_flags)
        send(producer, pkt)
        if i % 1000 == 0 and i > 0:
            time.sleep(0.01)

    print(f"      Sent 5000 SYN packets -> {dst_ip}:{dst_port}")


def inject_dga_domains(producer):
    """Simulate DGA queries — random-looking domains."""
    print("\n[2/4] Injecting: DGA domain queries")
    dga_domains = [
        "x8k4mq2p.net",
        "ajf83hdkw.com",
        "qz7mn4bx9.org",
        "hd93kxm2p.info",
        "vbnm45kld.top",
        "r9xk3mwp7.xyz",
        "kj8n3mxpq.club",
        "w4xk9mn2.biz",
    ]

    for domain in dga_domains:
        pkt = make_pkt("192.168.1.50", "8.8.8.8", 54321, 53,
                       protocol=17, pkt_len=80, payload_len=60,
                       tcp_flags=None, dns_query=domain)
        send(producer, pkt)
        time.sleep(0.05)

    print(f"      Sent {len(dga_domains)} DGA domain queries")


def inject_encrypted_malware(producer):
    """Simulate C2 beacon: regular small packets, non-std port, low volume."""
    print("\n[3/4] Injecting: Encrypted Malware C2 beacon (port 9999, regular timing)")
    src_ip = "192.168.1.50"
    dst_ip = "91.234.56.78"
    dst_port = 9999

    # Regular beaconing: 10 outbound, 10 inbound, uniform timing
    for i in range(10):
        # Outbound beacon
        pkt = make_pkt(src_ip, dst_ip, 50100, dst_port, pkt_len=120, payload_len=80)
        send(producer, pkt)
        time.sleep(0.1)

        # Inbound response
        pkt = make_pkt(dst_ip, src_ip, dst_port, 50100, pkt_len=400, payload_len=350)
        send(producer, pkt)
        time.sleep(0.1)

    print(f"      Sent 20 packets (10 out + 10 in, regular 100ms intervals)")


def inject_exfiltration(producer):
    """Simulate bulk data exfiltration: heavy upload, tiny responses."""
    print("\n[4/4] Injecting: Data Exfiltration (bulk upload to port 443)")
    src_ip = "192.168.1.50"
    dst_ip = "185.100.200.50"
    dst_port = 443

    # Initial SYN/ACK
    syn_flags = {"syn": True, "ack": False, "rst": False, "fin": False, "psh": False, "urg": False}
    pkt = make_pkt(src_ip, dst_ip, 51000, dst_port, pkt_len=60, payload_len=0, tcp_flags=syn_flags)
    send(producer, pkt)

    ack_flags = {"syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
    psh_flags = {"syn": False, "ack": True, "rst": False, "fin": False, "psh": True, "urg": False}

    # 500 large outbound packets (exfiltrating data)
    for i in range(500):
        pkt = make_pkt(src_ip, dst_ip, 51000, dst_port, pkt_len=1460, payload_len=1400, tcp_flags=psh_flags)
        send(producer, pkt)
        if i % 100 == 0 and i > 0:
            time.sleep(0.01)

    # Only 5 tiny responses (server ACKs)
    for _ in range(5):
        pkt = make_pkt(dst_ip, src_ip, dst_port, 51000, pkt_len=60, payload_len=0, tcp_flags=ack_flags)
        send(producer, pkt)

    print(f"      Sent 506 packets (500 upload + 5 ACKs + 1 SYN)")


def main():
    print("=" * 60)
    print("ALL-THREATS INJECTION TEST")
    print("=" * 60)
    print(f"Kafka: {KAFKA_BROKER} -> {KAFKA_TOPIC}")

    producer = Producer({"bootstrap.servers": KAFKA_BROKER, "acks": "1"})

    inject_ddos_syn_flood(producer)
    inject_dga_domains(producer)
    inject_encrypted_malware(producer)
    inject_exfiltration(producer)

    remaining = producer.flush(timeout=10)
    print(f"\n[*] Flush complete. Remaining: {remaining}")
    print("\n" + "=" * 60)
    print("INJECTION COMPLETE - wait 15s then check:")
    print("  docker-compose logs --tail 40 feature-extractor")
    print("  Dashboard: http://localhost:3000")
    print("=" * 60)


if __name__ == "__main__":
    main()
