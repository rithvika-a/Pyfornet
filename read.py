import json
from pathlib import Path


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