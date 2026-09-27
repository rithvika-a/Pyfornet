import json
from pathlib import Path


def custody_logger(func, session_path, **details):
    custody_path = Path(session_path) / "custody_logs.jsonl"

    log_entry = {
        "description": func.replace("_", " "),
        "session_id": Path(session_path).name,
        **details
                }

    try:
        with open(custody_path, "a", encoding="utf-8") as file:
            json.dump(log_entry, file, separators=(",", ":"))
            file.write("\n")

    except OSError as e:
        print(f"Could not write to chain of custody log: {e}")


def custody_reader(session_path):
    custody_path = Path(session_path) / "custody_logs.jsonl"
    custody_logs = []

    try:
        with open(custody_path, "r", encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    custody_logs.append(line)
                except json.JSONDecodeError:
                    continue

                if not isinstance(entry, dict):
                    continue

    except FileNotFoundError:
        print(f"Log file does not exist: {custody_path}")
    except OSError as e:
        print(f"Could not read log file: {e}")

    return custody_logs