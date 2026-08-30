"""List all network interfaces as scapy sees them (for --interface selection)."""
import scapy.arch.windows as w

print("=" * 70)
print("SCAPY INTERFACES (use the 'name' column for --interface)")
print("=" * 70)
for i in w.get_windows_if_list():
    name = i.get("name", "?")
    desc = i.get("description", "?")
    ips = i.get("ips", [])
    ipv4 = [ip for ip in ips if ":" not in ip]
    print(f"\nName        : {name}")
    print(f"Description : {desc}")
    print(f"IPs         : {ipv4}")
