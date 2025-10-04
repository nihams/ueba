
import os
import re
import json
import csv
from datetime import datetime

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
    
    # --- Auth Logs ---
    with open(os.path.join(raw_dir, "auth.log"), "r") as f:
        for line in f:
            if match := auth_log_re.match(line):
                data = match.groupdict()
                events.append({
                    "timestamp": parse_syslog_time(data['timestamp']).isoformat() + "Z",
                    "event_type": "auth", "action": "login",
                    "user_id": data['user_id'], "host": data['host'],
                    "src_ip": data['src_ip'], "src_port": int(data['src_port']),
                    "status": "success" if data['status'] == 'Accepted' else 'failure',
                    "raw": line.strip()
                })

    # --- Firewall Logs ---
    with open(os.path.join(raw_dir, "firewall.log"), "r") as f:
        for line in f:
            if match := fw_log_re.match(line):
                data = match.groupdict()
                events.append({
                    "timestamp": parse_syslog_time(data['timestamp']).isoformat() + "Z",
                    "event_type": "network", "action": data['action'].lower(),
                    "host": data['host'], "src_ip": data['src_ip'],
                    "src_port": int(data['src_port']), "dst_ip": data['dst_ip'],
                    "dst_port": int(data['dst_port']), "bytes": int(data['bytes']),
                    "raw": line.strip()
                })

    # --- File Audit Logs ---
    with open(os.path.join(raw_dir, "file_audit.csv"), "r") as f:
        for row in csv.DictReader(f):
            events.append({
                "timestamp": row['timestamp'], "event_type": "file",
                "action": row['action'].lower(), "user_id": row['user'],
                "resource": row['path'], "bytes": int(row['bytes']),
                "raw": f"{row['timestamp']},{row['user']},{row['path']},{row['action']},{row['bytes']}"
            })

    # --- Endpoint Process Logs ---
    with open(os.path.join(raw_dir, "endpoint_proc.jsonl"), "r") as f:
        for line in f:
            data = json.loads(line)
            events.append({
                "timestamp": data['timestamp'], "event_type": "process",
                "action": "execute", "user_id": data['user'],
                "host": data['host'], "process": data['process'],
                "raw": line.strip()
            })
            
    # --- Windows Event Logs ---
    with open(os.path.join(raw_dir, "windows_events.jsonl"), "r") as f:
        for line in f:
            data = json.loads(line)
            events.append({
                "timestamp": data['TimeCreated'], "event_type": "windows",
                "action": "service_install" if data.get('EventID') == 7045 else "unknown",
                "user_id": data['User'], "host": data['Host'],
                "raw": line.strip()
            })

    events.sort(key=lambda x: x['timestamp'])

    with open(out_file, "w") as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
            
    print(f"Successfully normalized {len(events)} events into '{out_file}'")

if __name__ == "__main__":
    normalize_all_logs()