import argparse
import os
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import get_if_list

from capture import capture_packet, permissions, session_path, pcap_path, log_path
from hash import update_manifest, verify_file_integrity
from read import read_logs
from report import write_report
from custody import custody_logger, custody_reader

captures_path = Path("Captures")

if not os.path.exists(captures_path):
    os.mkdir(captures_path)

    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')
    
    permissions("session_dir", captures_path, sudo_uid, sudo_gid)


def run_capture(args):
    interface = ""

    try:
        ipaddress.ip_address(args.ip)
        if not (args.hostname).isspace():
            if args.interface in get_if_list():
                interface = args.interface

            elif not args.interface:
                interface = "default"

            else:
                print(
                    f"Interface '{args.interface}' not found. "
                    f"Available interfaces: {get_if_list()}"
                )
        else:
            print("Hostname not provided.")

    except ValueError:
        print("Invalid IP address provided.")

    if interface:
        print(f"Starting capture on interface: {interface}")
        print(f"Machine IP: {args.ip}")
        print(f"Hostname: {args.hostname}")

        status, manifest_entry = capture_packet(args.ip, interface, args.hostname)

        if status:
            custody_logger(
                "capture_started",
                session_path,
                timestamp=manifest_entry["capture_start"],
                interface=interface,
                hostname=args.hostname,
            )
            
            manifest_path = update_manifest(session_path, manifest_entry, pcap_path, log_path)

            custody_logger(
                "capture_ended",
                session_path,
                timestamp=manifest_entry["capture_end"],
                files_produced=[Path(pcap_path).name, Path(log_path).name, manifest_path],
                hash_computed=[manifest_entry["evidence_hash"], manifest_entry["log_hash"]],
            )

            sudo_uid = os.environ.get('SUDO_UID')
            sudo_gid = os.environ.get('SUDO_GID')

            permissions("output_files", session_path, sudo_uid, sudo_gid)

            print(f"Session saved to: {session_path}")
            print(
                f"Run 'python3 main.py report -f {session_path}' "
                "to generate a summary of this session."
            )


def run_report(args):
    session_dir = Path(args.filepath)

    if not session_dir.exists():
        print(f"{session_dir} does not exist.")
        return

    print("Verifying file integrity before generating report...")
    verified, manifest_entry = verify_file_integrity(session_dir)

    if not verified:
        print("Integrity check failed. Halting report generation.")
        custody_logger(
            "integrity_failed",
            session_dir,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        return

    custody_logger(
        "integrity_verified",
        session_dir,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    results = read_logs(session_dir)
    custody_logs = custody_reader(session_dir)

    custody_logger(
        "evidence_logs_read",
        session_dir,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    
    report_text, report_path = write_report(session_dir, manifest_entry, results, custody_logs)

    custody_logger(
        "report_generated",
        session_dir,
        timestamp=datetime.now(timezone.utc).isoformat(),
        file_produced=Path(report_path).name,
    )

    if args.print_console:
        print(report_text)

        custody_logger(
            "report_printed",
            session_dir,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
    else:
        print(f"Report generated and saved in {report_path}.")


def main():
    description = "Pyfornet: Network-Based Intrusion Detection System (single-host)"
    parser = argparse.ArgumentParser(description=description)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser(
        "capture", 
        help="Start a live network capture and detection session. (sudo required)"
        )
    capture_parser.add_argument(
        "-i", "--interface", required=False, 
        help="Interface to capture on (optional)"
        )
    capture_parser.add_argument(
        "-ip", "--ip", required=True, 
        help="Your device's IP address"
        )
    capture_parser.add_argument(
        "-hn", "--hostname", required=True, 
        help="Hostname for this session/device"
        )
    capture_parser.set_defaults(func=run_capture)

    report_parser = subparsers.add_parser(
        "report", 
        help="Generate a report from a completed capture session"
        )
    report_parser.add_argument(
        "-f", "--filepath", required=True,
        help="Path to the session directory (e.g. Captures/session_2026-08-31_12-00)"
        )
    report_parser.add_argument(
        "--print-console", action="store_true", 
        help="Print report to console"
        )
    report_parser.set_defaults(func=run_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
