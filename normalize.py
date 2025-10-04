import os
import json
import csv
import re
from dateutil import parser as date_parser
from datetime import datetime

# --- Configuration ---
RAW_DIR = "data/raw"
OUT_DIR = "data/normalized"
OUT_FILE = os.path.join(OUT_DIR, "events.jsonl")

# --- Regex Parsers for unstructured logs ---
AUTH_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<result>Accepted|Failed)\s+password for '
    r'(?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)'
)

# --- Parser Functions for each log type ---

def parse_auth_line(line):
    """Parses a line from auth.log into the canonical format."""
    match = AUTH_RE.search(line)
    if not match:
        return None
    
    m = match.groupdict()
    # Reconstruct timestamp with the current year to make it parseable
    ts_str = f"{m['month']} {m['day']} {datetime.utcnow().year} {m['time']}"
    try:
        ts = date_parser.parse(ts_str).isoformat() + "Z"
    except date_parser.ParserError:
        ts = datetime.utcnow().isoformat() + "Z" # Fallback

    return {
        "timestamp": ts,
        "event_type": "auth",
        "action": "login",
        "user_id": m.get("user"),
        "host": m.get("host"),
        "src_ip": m.get("src_ip"),
        "src_port": int(m.get("src_port", 0)),
        "status": "success" if m.get("result") == "Accepted" else "failure",
        "raw": line.strip()
    }

def parse_file_audit_row(row):
    """Parses a row from file_audit.csv into the canonical format."""
    # Expected columns: timestamp, user, path, action, bytes
    return {
        "timestamp": row.get('timestamp'),
        "event_type": "file",
        "action": row.get('action', '').lower(),
        "user_id": row.get('user'),
        "resource": row.get('path'),
        "bytes": int(row.get('bytes', 0)),
        "raw": ",".join(row.values())
    }

def parse_endpoint_json(line):
    """Parses a JSON line from endpoint_proc.jsonl into the canonical format."""
    try:
        j = json.loads(line)
        return {
            "timestamp": j.get("timestamp"),
            "event_type": "process",
            "action": "execute",
            "user_id": j.get("user"),
            "host": j.get("host"),
            "process": j.get("process"),
            "raw": line.strip()
        }
    except json.JSONDecodeError:
        return None

def parse_web_proxy_json(line):
    """
    Parses a JSON line from the new web_proxy.jsonl into the canonical format.
    This is the key new function.
    """
    try:
        j = json.loads(line)
        # Map the web proxy fields to our canonical schema
        return {
            "timestamp": j.get("timestamp"),
            "event_type": "web",
            "action": j.get("http_method", "").lower(),
            "user_id": j.get("user_id"),
            "host": j.get("host"),
            "src_ip": j.get("src_ip"),
            "dst_ip": j.get("dst_ip"),
            "dst_hostname": j.get("dst_hostname"),
            "http_method": j.get("http_method"),
            "bytes_out": j.get("bytes_out"),
            "bytes_in": j.get("bytes_in"),
            "user_agent": j.get("user_agent"),
            "url_category": j.get("url_category"),
            "status_code": j.get("status_code"),
            "status": "success" if str(j.get("status_code")).startswith('2') else "failure",
            "raw": line.strip()
        }
    except json.JSONDecodeError:
        return None

def normalize_all_logs(raw_dir=RAW_DIR, out_file=OUT_FILE):
    """
    Reads all raw log files, processes them with the correct parser,
    and writes the unified events to a single sorted JSONL file.
    """
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    
    all_events = []
    
    # Define which parser to use for each file
    file_parsers = {
        "auth.log": ("line", parse_auth_line),
        "endpoint_proc.jsonl": ("line", parse_endpoint_json),
        "web_proxy.jsonl": ("line", parse_web_proxy_json), # <-- ADDED NEW FILE
        "file_audit.csv": ("csv", parse_file_audit_row)
    }

    print("Starting log normalization process...")
    for filename, (file_type, parser_func) in file_parsers.items():
        filepath = os.path.join(raw_dir, filename)
        if not os.path.exists(filepath):
            print(f"  - Warning: '{filename}' not found, skipping.")
            continue
        
        print(f"  - Processing '{filename}'...")
        with open(filepath, "r") as f:
            if file_type == "line":
                for line in f:
                    if event := parser_func(line):
                        all_events.append(event)
            elif file_type == "csv":
                reader = csv.DictReader(f)
                for row in reader:
                    if event := parser_func(row):
                        all_events.append(event)

    if not all_events:
        print("No events were processed. Is the data/raw directory populated?")
        return

    # Sort all events by timestamp to create a chronological record
    print("Sorting all events by timestamp...")
    all_events.sort(key=lambda x: x.get('timestamp', ''))

    # Write to the canonical output file
    with open(out_file, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + '\n')
            
    print(f"\n✅ Successfully normalized {len(all_events)} events into '{out_file}'")

if __name__ == "__main__":
    normalize_all_logs()