"""Debug: inject clean C2 beacon flows directly to Kafka to test the detector."""
import json, time
from confluent_kafka import Producer

p = Producer({"bootstrap.servers": "localhost:9092", "acks": "1"})

src = "192.168.99.50"
dst = "203.0.113.77"
dport = 1524
base = time.time()

# 12 beacons, one every 3 seconds, each a separate established connection
# (fwd + bwd packets, small payload). Spread over 36s = 4 windows.
for i in range(12):
    ts_us = int((base + i * 3.0) * 1_000_000)
    sport = 40000 + i  # different source port per connection = separate flow
    # Two packets: outbound beacon + inbound reply (so bwd_packets > 0)
    for direction in ("out", "in"):
        if direction == "out":
            s_ip, d_ip, s_p, d_p, plen = src, dst, sport, dport, 300
            flags = {"syn": False, "ack": True, "rst": False, "fin": False, "psh": True, "urg": False}
        else:
            s_ip, d_ip, s_p, d_p, plen = dst, src, dport, sport, 200
            flags = {"syn": False, "ack": True, "rst": False, "fin": False, "psh": True, "urg": False}
        pkt = {
            "src_ip": s_ip, "dst_ip": d_ip, "src_port": s_p, "dst_port": d_p,
            "protocol": 6, "timestamp_us": ts_us + (0 if direction == "out" else 20000),
            "packet_len": plen, "payload_len": plen - 40, "tcp_flags": flags,
            "dns_query": None, "ingest_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        key = f"{s_ip}:{s_p}-{d_ip}:{d_p}"
        p.produce("flow-records", key=key.encode(), value=json.dumps(pkt).encode())
        p.poll(0)
    print(f"beacon {i+1}/12 injected (ts offset {i*3.0}s)")
    time.sleep(3.0)  # real-time pacing so it spans multiple 10s windows

p.flush()
print("done - wait ~15s then check logs")
