import argparse
import os
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import get_if_list

from capture import capture_packet, session_path
from hash import verify_file_integrity
from report import write_report
from custody import custody_logger

captures_path = Path("Captures")

if not os.path.exists(captures_path):
    os.mkdir(captures_path)


def run_capture(args):
    try:
        ipaddress.ip_address(args.ip)
        if not (args.hostname).isspace():
            if args.interface in get_if_list():
                print(f"Starting capture on interface: {args.interface}")
                print(f"Machine IP: {args.ip}")
                print(f"Hostname: {args.hostname}")

                if capture_packet(args.ip, args.interface, args.hostname):
                    print(f"Session saved to: {session_path}")
                    print(
                        f"Run 'python3 main.py report -f {session_path}' "
                        "to generate a summary of this session."
                    )

            elif not args.interface:
                print("Starting capture on interface: default")
                print(f"Machine IP: {args.ip}")
                print(f"Hostname: {args.hostname}")

                if capture_packet(args.ip, "default", args.hostname):
                    print(f"Session saved to: {session_path}")
                    print(
                        f"Run 'python3 main.py report -f {session_path}' "
                        "to generate a summary of this session."
                    )

            else:
                print(
                    f"Interface '{args.interface}' not found. "
                    f"Available interfaces: {get_if_list()}"
                )
        else:
            print("Hostname not provided.")

    except ValueError:
        print("Invalid IP address provided.")


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

    report_text, report_path = write_report(session_dir, manifest_entry)

    custody_logger(
        "report_generated",
        session_dir,
        timestamp=datetime.now(timezone.utc).isoformat(),
        file_produced=str(report_path),
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
    parser = argparse.ArgumentParser(description="pyfornet: Network Anomaly Detection and Reporting Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser(
        "capture", 
        help="Start a live network capture and detection session. (sudo permissions required)"
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
