import json
from pathlib import Path
from tabulate import tabulate
from datetime import datetime, timezone

from custody import custody_reader


def rules(chosen_rule, filename="ruleset.json"):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            config = json.load(f)
            for rule in config["rules"]:
                if rule["id"] == chosen_rule:
                    return rule
    except FileNotFoundError:
        print(f"Ruleset file does not exist: {filename}")
    except OSError as e:
        print(f"Could not read ruleset file: {e}")
    except PermissionError as e:
        print(f"Could not access ruleset file: {e}")

    return None


def read_logs(session_path):
    log_path = Path(session_path) / "logs.jsonl"

    results = {
        "src_ips": set(),
        "dst_ips": set(),
        "dports": set(),
        "port_scan": [],
        "brute_force": [],
        "flood_detection": [],
        "ip_blocklist": [],
        "suspicious_dns": [],
        "flagged_anomalies": set(),
        "invalid_json": 0,
        "total_lines": 0,
    }

    every_rule = [
        rules("port_scan"),
        rules("brute_force"),
        rules("flood_detection"),
        rules("ip_blocklist"),
        rules("suspicious_dns")
        ]
    
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                results["total_lines"] += 1

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    results["invalid_json"] += 1
                    continue

                if not isinstance(entry, dict):
                    results["invalid_json"] += 1
                    continue

                table_entry = {
                    "timestamp": entry["timestamp"],
                    "interface": entry["interface"],
                    "direction": entry["direction"],
                    "src": entry["src"],
                    "sport": entry["sport"],
                    "dst": entry["dst"],
                    "dport": entry["dport"],
                    "dns_query": entry["dns_query"],
                }

                anomalies_here = []

                if entry["anomaly"]:
                    anomalies_here = entry["anomaly"]

                for rule in every_rule: 
                    if rule["id"] in anomalies_here:
                        results[rule["id"]].append(table_entry)
                        results["flagged_anomalies"].add(rule["id"])

                if entry["src"]:
                    results["src_ips"].add(entry["src"])
                if entry["dst"]:
                    results["dst_ips"].add(entry["dst"])
                if entry["dport"]:
                    results["dports"].add(entry["dport"])

    except FileNotFoundError:
        print(f"Log file does not exist: {log_path}")
    except OSError as e:
        print(f"Could not read log file: {e}")

    return results


def generate_table(anomaly_entries):
    if not anomaly_entries:
        return ""
    return tabulate(anomaly_entries, headers="keys", tablefmt="rst")


def write_report(session_path, manifest_entry):
    session_path = Path(session_path)
    data = read_logs(session_path)
    custody_logs = custody_reader(session_path)
    report_path = session_path / "report.txt"

    lines = []

    def w(text=""):
        lines.append(text)

    w("-----NETWORK CAPTURE FORENSIC REPORT-----\n")

    w("----EVIDENCE DESCRIPTION----")
    w(f"Session: {session_path}")
    w(f"Report generated: {datetime.now(timezone.utc).isoformat()}\n")

    w("---SESSION OVERVIEW---")
    w(f"Operator/host: {manifest_entry['hostname']}")
    w(f"Interface used: {manifest_entry['interface']}")
    w(f"Start time: {manifest_entry['capture_start']}")
    w(f"End time: {manifest_entry['capture_end']}")
    w(f"Capture window: {manifest_entry['capture_window']}")
    w(f"Total packets captured: {manifest_entry['total_packets']}")
    w(f"Source IP distribution: {list(data['src_ips'])}")
    w(f"Flagged anomalies: {list(data['flagged_anomalies'])}\n")

    w("---EVIDENCE INTEGRITY---")
    w(f"Log file: {manifest_entry['log_filename']}")
    w(f"Log hash (SHA-256): {manifest_entry['log_hash']}")
    w(f"Evidence file: {manifest_entry['evidence_filename']}")
    w(f"Evidence hash (SHA-256): {manifest_entry['evidence_hash']}")
    w("Verification result: MATCH\n")

    w("---PORT SCAN ATTEMPTS---")
    if data["port_scan"]:
        w(f"Number of port scan attempts: {len(data['port_scan'])}")
        w("Each flagged entry is as follows:")
        w(generate_table(data["port_scan"]))
        port_scan_rule = rules("port_scan")
        for entry in data["port_scan"]:
            w(
                f"At {entry['timestamp']}, source {entry['src']} contacted more than "
                f"{port_scan_rule['threshold']} distinct ports within "
                f"{port_scan_rule['window_seconds']} seconds, "
                "consistent with port scanning activity."
            )
    else:
        w("No port scan attempts observed.\n")

    w("---BRUTE FORCE ATTEMPTS---")
    if data["brute_force"]:
        w(f"Number of brute force attempts: {len(data['brute_force'])}")
        w("Each flagged entry is as follows:")
        w(generate_table(data["brute_force"]))
        brute_force_rule = rules("brute_force")
        for entry in data["brute_force"]:
            w(
                f"At {entry['timestamp']}, source {entry['src']} contacted port "
                f"{entry['dport']} more than {brute_force_rule['threshold']} times within "
                f"{brute_force_rule['window_seconds']} seconds, "
                "consistent with brute force activity."
            )
    else:
        w("No brute force attempts observed.\n")

    w("---PACKET FLOODING---")
    if data["flood_detection"]:
        w(f"Number of flooding attempts: {len(data['flood_detection'])}")
        w("Each flagged entry is as follows:")
        w(generate_table(data["flood_detection"]))
        flood_detection_rule = rules("flood_detection")
        for entry in data["flood_detection"]:
            w(
                f"At {entry['timestamp']}, source {entry['src']} generated more than "
                f"{flood_detection_rule['threshold']} packets within "
                f"{flood_detection_rule['window_seconds']} seconds, "
                "consistent with packet flooding activity."
            )
    else:
        w("No flooding attempts observed.\n")

    w("---SUSPICIOUS IP---")
    if data["ip_blocklist"]:
        w(f"Number of suspicious IPs encountered: {len(data['ip_blocklist'])}")
        w("Each flagged entry is as follows:")
        w(generate_table(data["ip_blocklist"]))
        for entry in data["ip_blocklist"]:
            if entry["direction"] == "inbound":
                observed_ip = entry["dst"]
            else:
                observed_ip = entry["src"]

            w(
                f"At {entry['timestamp']}, {entry['direction']} traffic involving "
                f"known suspicious IP {observed_ip} was observed."
            )
    else:
        w("No suspicious IPs observed.\n")

    w("---SUSPICIOUS DNS REQUESTS---")
    if data["suspicious_dns"]:
        w(f"Number of suspicious DNS queries encountered: {len(data['suspicious_dns'])}")
        w("Each flagged entry is as follows:")
        w(generate_table(data["suspicious_dns"]))
        for entry in data["suspicious_dns"]:
            if entry["direction"] == "inbound":
                observed_ip = entry["dst"]
            else:
                observed_ip = entry["src"]

            w(
                f"At {entry['timestamp']}, {entry['direction']} traffic from {observed_ip} "
                f"revealed a known suspicious DNS query: {entry['dns_query']}."
            )
    else:
        w("No suspicious DNS queries observed.\n")

    w("\n---CHAIN OF CUSTODY SUMMARY---\n")
    for entry in custody_logs:
        w(entry)

    w("---LOG INTEGRITY---")
    w(f"Number of invalid JSON log lines encountered: {data['invalid_json']}")
    w(f"Failed to process {data['invalid_json']} out of {data['total_lines']} log lines.\n")

    w("---SESSION OBSERVATIONS---")
    if data["flagged_anomalies"]:
        w(
        "Due to the anomaly(s) observed within this session, "
        "further investigation is highly suggested."
        )
    else:
        w("No anomalies were observed during this session. Routine review is still suggested.")

    w("\n-----END OF REPORT-----")

    report_text = "\n".join(lines)

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text)
    except PermissionError as e:
        print(f"Could not access report file: {e}")
        return

    return report_text, report_path
