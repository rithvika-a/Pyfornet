import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def compute_file_hash(filepath):
    filepath = Path(filepath)
    if not filepath.exists():
        return "No hash generated: file is not found"
    
    if not filepath.is_file():
        return "No hash generated: path is not a file"

    with open(filepath, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def update_manifest(session_path, entry, pcap_path, log_path):
    session_path = Path(session_path)
    manifest_path = session_path / "manifest.json"

    entry["evidence_hash"] = compute_file_hash(pcap_path)
    entry["log_hash"] = compute_file_hash(log_path)
    entry["hashed_at"] = datetime.now(timezone.utc).isoformat()

    if manifest_path.exists():
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)

    else:
        data = {"entries": []}

    data["entries"].append(entry)

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return manifest_path


def verify_file_integrity(session_path):
    session_path = Path(session_path)
    manifest_path = session_path / "manifest.json"

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)

    except json.JSONDecodeError as e:
        print(f"Could not read manifest file: {e}")
        return False, None
    except OSError as e:
        print(f"Could not read manifest file: {e}")
        return False, None

    entries = []
    if data["entries"]:
        entries = data["entries"]

    if not entries:
        print(f"No manifest entries found in {manifest_path}")
        return False, None

    latest_entry = entries[-1]

    evidence_path = session_path / latest_entry["evidence_filename"]
    log_path = session_path / latest_entry["log_filename"]

    current_evidence_hash = compute_file_hash(evidence_path)
    current_log_hash = compute_file_hash(log_path)

    evidence_match = current_evidence_hash == latest_entry["evidence_hash"]
    log_match = current_log_hash == latest_entry["log_hash"]

    if evidence_match and log_match:
        print(
            f"MATCH — Both {latest_entry['evidence_filename']} and "
            f"{latest_entry['log_filename']} integrity verified "
            f"(hashed at {latest_entry['hashed_at']})"
            )
        return True, latest_entry

    if not evidence_match:
        print(
            f"MISMATCH — {latest_entry['evidence_filename']} "
            f"has been altered since {latest_entry['hashed_at']}"
            )
        print(f"Expected: {latest_entry['evidence_hash']}")
        print(f"Got:      {current_evidence_hash}")

    if not log_match:
        print(
            f"MISMATCH — {latest_entry['log_filename']} "
            f"has been altered since {latest_entry['hashed_at']}"
            )
        print(f"Expected: {latest_entry['log_hash']}")
        print(f"Got:      {current_log_hash}")

    return False, latest_entry
