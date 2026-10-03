import time
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


def ip_blocklist(src_ip, dst_ip):
    rule = rules("ip_blocklist")
    
    if rule is None:
        print("ip_blocklist rule not found in ruleset.json. Skipping check.")
        return

    blocklist_file = Path(rule["blocklist_file"])

    try:
        with open(blocklist_file, "r", encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                if src_ip == line.strip():
                    print("ALERT: IP matched from blacklist")
                    return rule["id"]

                elif dst_ip == line.strip():
                    print("ALERT: IP matched from blacklist")
                    return rule["id"]
                
    except FileNotFoundError:
        print(f"Blocklist file does not exist: {rule['blocklist_file']}")
    except OSError as e:
        print(f"Could not read blocklist file: {e}")
    except PermissionError as e:
        print(f"Could not access blocklist file: {e}")


def suspicious_dns(dns_query):
    rule = rules("suspicious_dns")

    if rule is None:
        print("suspicious_dns rule not found in ruleset.json. Skipping check.")
        return

    watchlist_file = Path(rule["watchlist_file"])

    try:
        with open(watchlist_file, "r", encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                if dns_query == line.strip():
                    print("ALERT: DNS matched from watchlist file")
                    return rule["id"]
                
    except FileNotFoundError:
        print(f"Watchlist file does not exist: {rule['watchlist_file']}")
    except OSError as e:
        print(f"Could not read watchlist file: {e}")
    except PermissionError as e:
        print(f"Could not access watchlist file: {e}")


port_scan_tracker = {}
port_scan_alerted = {}
brute_force_tracker = {}
brute_force_alerted = {}
flood_detection_tracker = {}
flood_detection_alerted = {}


def port_scan(src_ip, dport):
    rule = rules("port_scan")
    if rule is None:
        print("port_scan rule not found in ruleset.json. Skipping check.")
        return

    if dport is None:
        return

    if src_ip in port_scan_alerted:
        if time.time() - port_scan_alerted[src_ip] > rule["cooldown"]:
            port_scan_alerted.pop(src_ip)
        else:
            return

    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = {"ports": set(), "first_seen": time.time()}

    entry = port_scan_tracker[src_ip]

    if time.time() - entry["first_seen"] > rule["window_seconds"]:
        entry["ports"] = set()
        entry["first_seen"] = time.time()

    entry["ports"].add(dport)

    if len(entry["ports"]) >= rule["threshold"]:
        print("ALERT: Port Scan Attempt Detected")
        port_scan_alerted[src_ip] = time.time()
        entry["ports"] = set()
        entry["first_seen"] = time.time()
        return rule["id"]


def brute_force(src_ip, dport):
    rule = rules("brute_force")
    if rule is None:
        print("brute_force rule not found in ruleset.json. Skipping check.")
        return

    if dport is None:
        return

    if src_ip in brute_force_alerted:
        if time.time() - brute_force_alerted[src_ip] > rule["cooldown"]:
            brute_force_alerted.pop(src_ip)
        else:
            return

    if src_ip not in brute_force_tracker:
        brute_force_tracker[src_ip] = {"ports": [], "first_seen": time.time()}

    entry = brute_force_tracker[src_ip]

    if time.time() - entry["first_seen"] > rule["window_seconds"]:
        entry["ports"] = []
        entry["first_seen"] = time.time()

    entry["ports"].append(dport)

    if len(set(entry["ports"])) == 1 and len(entry["ports"]) >= rule["threshold"]:
        print("ALERT: Brute Force Attempt Detected")
        brute_force_alerted[src_ip] = time.time()
        entry["ports"] = []
        entry["first_seen"] = time.time()
        return rule["id"]


def flood_detection(src_ip):
    rule = rules("flood_detection")
    if rule is None:
        print("flood_detection rule not found in ruleset.json. Skipping check.")
        return

    if src_ip in flood_detection_alerted:
        if time.time() - flood_detection_alerted[src_ip] > rule["cooldown"]:
            flood_detection_alerted.pop(src_ip)
        else:
            return

    if src_ip not in flood_detection_tracker:
        flood_detection_tracker[src_ip] = {"packets": 0, "first_seen": time.time()}

    entry = flood_detection_tracker[src_ip]

    if time.time() - entry["first_seen"] > rule["window_seconds"]:
        entry["packets"] = 0
        entry["first_seen"] = time.time()

    entry["packets"] += 1

    if entry["packets"] >= rule["threshold"]:
        print("ALERT: Flood of Packets Detected")
        flood_detection_alerted[src_ip] = time.time()
        entry["packets"] = 0
        entry["first_seen"] = time.time()
        return rule["id"]
