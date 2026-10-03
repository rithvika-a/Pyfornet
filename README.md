# Pyfornet: Network-Based Intrusion Detection System

A Python-based tool that captures live network traffic and detects suspicious activity using a configurable rule set. The tool mimics a real-world NIDS (Network-Based Intrusion Detection System), created for single-host operation. It also preserves captured evidence with forensic integrity features (hashing, chain-of-custody logging, and verification). This was built as a personal project to apply networking, digital forensics, and secure Python development concepts practically.

## Overview

> Pyfornet operates at a single-host scope, not enterprise-level deployment, but implements the same core network-based IDS techniques such as packet-level traffic analysis, rule-based anomaly detection, and alerting.

This tool combines three areas:
- **Networking** — live packet capture and analysis using `scapy`
- **Digital forensics** — evidence integrity (SHA-256 hashing, manifest files, chain-of-custody logging) and structured investigation-style reporting
- **Secure Python development** — input validation, safe file handling and error handling, and config-driven (not hardcoded) detection rules

## Features

- Live packet capture on a user-specified network interface (all interfaces if none provided)
- Real-time anomaly detection while capturing, including:
  - **Port scan detection** — flags a source IP contacting many number of distinct destination ports within a short window
  - **Brute-force detection** — flags a source IP repeatedly targeting the same port (e.g. repeated login attempts) within a window
  - **Flood/volume detection** — flags a source IP sending an unusually high volume of packets within a short window
  - **IP blocklist matching** — flags traffic to or from known-malicious IPs
  - **Suspicious DNS matching** — flags DNS queries to known-malicious domains
- Alert cooldown per source IP, preventing a single ongoing event from flooding the output with repeated alerts
- Evidence integrity: every capture session's `.pcap` and `.jsonl` files are hashed (SHA-256) and recorded in a manifest
- Append-only chain-of-custody logging of actions taken on each capture session
- Report generation summarising a completed session, with file integrity verification carried out before the report is produced
- Simple CLI (via `argparse`) for running captures and generating reports

## Requirements

- Python 3.9+
- Kali Linux or another Linux distribution (root/sudo privileges required for packet capture)
- See `requirements.txt` for Python package dependencies

## Installation

```bash
git clone https://github.com/rithvika-a/Pyfornet.git
cd pyfornet
pip install -r requirements.txt
```

## Usage

```bash
# Start a live capture and detection session (requires sudo due to raw socket access)
sudo python3 main.py capture -ip <your_device_ip> -hn <hostname> [-i <interface>]

# Generate a report for a specific session (sudo not required)
python3 main.py report -f <path_to_session_directory> [--print-console]
```

### Example

```bash
sudo python3 main.py capture -i eth0 -ip 214.4.74.181 -hn kali-vm
python3 main.py report -f Captures/session_2026-09-26_18-17 --print-console
```

## Project Structure

```
pyfornet/
  main.py               # CLI entry point (argparse)
  capture.py            # packet capture
  detect.py             # live detection logic
  hash.py               # hashing, manifest, verification
  custody.py            # chain-of-custody
  read.py               # reading evidence logs
  report.py             # report generation
  data/
    blacklist.txt       # FireHOL / AbuseIPDB-sourced IP blocklist
    watchlist.txt       # URLhaus-sourced domain/URL list
  Captures/
    session_[timestamp]/
      evidence.pcap
      logs.jsonl
      manifest.json
      custody_logs.jsonl
  requirements.txt
  README.md
```

## Detection Rule Design & Sources

Detection thresholds were chosen with reference to publicly documented industry practice rather than arbitrary guesses. These are intended as tunable starting points:

- **Flood/volume and brute-force thresholds** were sourced from Snort's own documented `rate_filter` and `detection_filter` examples. See: [Snort README.filters](https://www.snort.org/faq/readme-filters)
- **Port scan detection** does not use a single fixed "industry standard" threshold, because none is publicly published. Snort's own scan-detection preprocessor uses internally tuned sensitivity tiers rather than a documented number. Therefore, a deliberate design choice was made to baseline rate-based thresholds against my own environment. This tool's port scan threshold is treated as a tunable starting default, following that documented best practice.
- **General intrusion detection approach** follows the framework described in NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems (IDPS)*. This tool's detection rules (port scan, brute force, flood) fall conceptually under NIST's "Network Behaviour Analysis" (NBA) category, which examines network traffic to identify threats generating unusual traffic flows. See: [NIST SP 800-94, full guide](https://csrc.nist.gov/pubs/sp/800/94/final).
- **Attacker behaviour justification** (why scanning/reconnaissance activity is treated as suspicious) references MITRE ATT&CK techniques, specifically T1046 (Network Service Discovery) and T1595 (Active Scanning).
- **IP blocklist** is sourced from [FireHOL's aggregation of AbuseIPDB reports](https://iplists.firehol.org/?ipset=abuseipdb_1d) (≥90–100% abuse confidence, refreshed daily). A 30-day aggregated ipset was used as the primary blacklist.
- **Malicious domain/URL list** is sourced from [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/api/), a widely used open threat-intelligence feed for malware distribution infrastructure. Similarly, a 30-day aggregated set was used as the primary DNS watchlist.


## Forensic Design Notes

- Evidence is hashed (SHA-256) immediately after each capture session is finalised (both the `.pcap` file and the structured `logs.jsonl`), and both hashes are stored separately from the evidence itself, in `manifest.json`, so that tampering with the evidence cannot also alter its recorded fingerprint.
- A dedicated verification function (`verify_file_integrity`) re-hashes both evidence files on demand and compares them against the manifest, explicitly stating a match or mismatch for each.
- All actions taken on a capture session (capture start/end, integrity verified/failed, evidence logs read, report generated/printed) are recorded in an append-only chain-of-custody log (`custody_logs.jsonl`), distinct from the traffic logs themselves.
- Report generation re-verifies evidence integrity before producing a summary. Reports are only generated for sessions that pass verification; if verification fails, report generation halts instead of proceeding with unverified evidence.
- After a session finishes capturing, evidence files (`evidence.pcap`, `logs.jsonl`) are set read-only, and ownership of the session directory is restored to the invoking user (see Known Limitations below). This reflects the principle that raw evidence should be locked immediately after acquisition, not just hashed.

## Ethical Use

This tool is intended for use only on networks and systems you own or have explicit authorisation to monitor.

## Known Limitations / Future Work

- **Privilege scope:** packet capture (`capture`) requires `sudo`/root, since raw socket access is required. `report` does not need elevated privileges, since the session directory's ownership is corrected to the invoking user immediately upon creation, not just at the end of capture. This closes the original permission error seen when generating reports without `sudo`.
- **Output file ownership:** evidence and log files are created while the process is running as root, so their ownership is only corrected to the invoking user as the final step of a successful capture. If a capture were to fail between the session directory being created and that final step completing, the individual files (`logs.jsonl`, `evidence.pcap`, `manifest.json`, `custody_logs.jsonl`) could remain root-owned. This limits the user-scope of report generation, thereby making `sudo` a requirement for that `report` command to work.
- **Detection runs in real-time mode** (state is tracked per source IP while capturing), instead of the batch-based model this project started from. This became a deliberate choice once the batch-mode logic was proven to work, to better reflect my goal of live network capture through this tool, and to imitate real-world NIDS.
- **Thresholds are static defaults**, sourced from Snort's documented examples and general practitioner guidance. NIST's own guidance suggests that these should be baselined against actual network behaviour before being treated as authoritative for any real deployment.
- **The blacklist and watchlist do not update automatically.** Instead of an up-to-date, continuously refreshed set, a static 30-day snapshot was used. In a real-world deployment, these sets would need to be refreshed more frequently.
- **Detection state is per-process, in-memory** (e.g. `port_scan_tracker`, `flood_detection_tracker` in `detect.py`); it resets if the tool restarts and does not persist activity across multiple capture sessions.
- **Single-host only.** No multi-host or distributed traffic correlation; each session's detection state is isolated to one capture run on one machine.
- **Data file paths are relative to the current working directory**, not anchored to the script's own location. The tool must currently be run from the project root for `ruleset.json`'s file references to resolve correctly.
- **Limited rule coverage.** The current ruleset covers five detection categories; additional rules (e.g. suspicious TLDs, protocol anomalies) would provide more comprehensive coverage of the attack surface.

## Author

Rithvika — BSc Cyber Security, University of Warwick
