
import os
import re
import json
import csv
from datetime import datetime

# --- Configuration ---
RAW_DIR = "data/raw"
OUT_DIR = "data/normalized"
OUT_FILE = os.path.join(OUT_DIR, "events.jsonl")

auth_log_re = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<status>Accepted|Failed)\s+password\s+for\s+"
    r"(?P<user_id>\S+)\s+from\s+(?P<src_ip>\S+)\s+"
    r"port\s+(?P<src_port>\d+)"
)

fw_log_re = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+FIREWALL:\s+(?P<action>\S+)\s+"
    r"proto=TCP\s+src=(?P<src_ip>\S+):(?P<src_port>\d+)\s+"
    r"dst=(?P<dst_ip>\S+):(?P<dst_port>\d+)\s+bytes=(?P<bytes>\d+)"
)

def parse_syslog_time(timestamp_str):
    dt_obj = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
    return dt_obj.replace(year=datetime.now().year)

def normalize_all_logs(raw_dir=RAW_DIR, out_file=OUT_FILE):
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    events = []
    
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
            
    print(f"\nSuccessfully normalized {len(all_events)} events into '{out_file}'")

if __name__ == "__main__":
    normalize_all_logs()