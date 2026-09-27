from datetime import datetime, timezone
import json
import os
from pathlib import Path

from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, Raw, DNS, DNSQR

from detect import port_scan, brute_force, flood_detection, ip_blocklist, suspicious_dns


session_format = datetime.now().strftime("%Y-%m-%d_%H-%M")
session_path = Path(f"Captures/session_{session_format}")
pcap_path = session_path / "evidence.pcap"
log_path = session_path / "logs.jsonl"


class PacketHandler:
    def __init__(self, machine_ip, interface, log_path):
        self.machine_ip = machine_ip
        self.interface = interface
        self.log_path = log_path

    def handle_packet(self, packet):
        try:
            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst
                ttl = packet[IP].ttl
                direction = "inbound"
                proto = "Other"
                sport = None
                dport = None
                flags = None
                dns_query = None
                payload_size = 0
                anomaly = set()

                if src == self.machine_ip:
                    direction = "outbound"

                if packet.haslayer(TCP):
                    proto = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = str(packet[TCP].flags)

                if packet.haslayer(UDP):
                    proto = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport

                if packet.haslayer(ICMP):
                    proto = "ICMP"

                if packet.haslayer(Raw):
                    payload_size = len(packet[Raw].load)

                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    if packet[DNS].qr == 0:
                        dns_query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                        suspicious_dns_result = suspicious_dns(dns_query)
                        if suspicious_dns_result:
                            anomaly.add(suspicious_dns_result)

                port_scan_result = port_scan(src, dport)
                if port_scan_result:
                    anomaly.add(port_scan_result)

                brute_force_result = brute_force(src, dport)
                if brute_force_result:
                    anomaly.add(brute_force_result)

                flood_result = flood_detection(src)
                if flood_result:
                    anomaly.add(flood_result)

                blocklist_result = ip_blocklist(src, dst)
                if blocklist_result:
                    anomaly.add(blocklist_result)

                log_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "interface": self.interface,
                    "direction": direction,
                    "src": src,
                    "sport": sport,
                    "dst": dst,
                    "dport": dport,
                    "proto": proto,
                    "ttl": ttl,
                    "dns_query": dns_query,
                    "flags": flags,
                    "packet_length": len(packet),
                    "payload_size": payload_size,
                    "anomaly": list(anomaly),
                    }

                with open(self.log_path, "a", encoding="utf-8") as f:
                    json.dump(log_entry, f, separators=(",", ":"))
                    f.write("\n")

        except Exception as e:
            print(f"Error handling packet: {e}")


def permissions(func, session_path, sudo_uid=None, sudo_gid=None):
    session_path = Path(session_path)

    if sudo_uid and sudo_gid:
        if func == "session_dir":
            try:
                os.chown(session_path, int(sudo_uid), int(sudo_gid))

            except OSError as e:
                print(f"Could not change ownership of {session_path}: {e}")

        if func == "output_files":
            for file in session_path.iterdir():
                try:
                    os.chown(file, int(sudo_uid), int(sudo_gid))

                except OSError as e:
                    print(f"Could not change ownership of {file}: {e}")

                
def capture_packet(machine_ip, interface, hostname):
    print("Starting capture... press Ctrl+C to stop")
    handler = PacketHandler(machine_ip=machine_ip, interface=interface, log_path=log_path)
    sniffed_pkts = []

    try:
        if not os.path.exists(session_path):
            os.mkdir(session_path)

            sudo_uid = os.environ.get('SUDO_UID')
            sudo_gid = os.environ.get('SUDO_GID')

            permissions("session_dir", session_path, sudo_uid, sudo_gid)

        capture_start = datetime.now(timezone.utc)

        if interface == "default":
            sniffed_pkts = sniff(
                prn=handler.handle_packet, 
                promisc=False, 
                store=True
                )
            
        else:
            sniffed_pkts = sniff(
                prn=handler.handle_packet, 
                iface=interface, 
                promisc=False, 
                store=True
                )

        capture_end = datetime.now(timezone.utc)
        capture_window = str(capture_end - capture_start)

    except KeyboardInterrupt:
        print("Capture ended.")
        capture_end = datetime.now(timezone.utc)
        capture_window = str(capture_end - capture_start)

    finally:
        if len(sniffed_pkts):
            wrpcap(str(pcap_path), sniffed_pkts)

            manifest_entry = {
                "evidence_filename": Path(pcap_path).name,
                "log_filename": Path(log_path).name,
                "capture_start": capture_start.isoformat(),
                "capture_end": capture_end.isoformat(),
                "capture_window": capture_window,
                "interface": interface,
                "hostname": hostname,
                "total_packets": len(sniffed_pkts),
                }

            return True, manifest_entry
        
        else:
            print("No packets captured. Halting evidence and log creation.")

            if os.path.exists(session_path): 
                os.rmdir(session_path)

            return False, None
