#!/usr/bin/env python3
"""
normalize.py
Reads data/raw/* and writes data/normalized/events.jsonl using the canonical schema.
"""
import os, json, re
from dateutil import parser
from datetime import datetime

RAW_DIR = "data/raw"
OUT_DIR = "data/normalized"
OUT_FILE = os.path.join(OUT_DIR, "events.jsonl")

# Helpers
def iso_or_none(s):
    try:
        return parser.parse(s).astimezone().isoformat()
    except Exception:
        return None

# Parsers
AUTH_RE = re.compile(r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<result>Accepted|Failed)\s+password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)')
NGINX_RE = re.compile(r'(?P<src_ip>\S+) - (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<resource>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+)')
FW_RE = re.compile(r'(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+FIREWALL:\s+(?P<action>\w+)\s+proto=(?P<proto>\S+)\s+src=(?P<src_ip>[^:]+):(?P<src_port>\d+)\s+dst=(?P<dst_ip>[^:]+):(?P<dst_port>\d+)')

def parse_auth_line(line):
    m = AUTH_RE.search(line)
    if not m:
        return None
    # reconstruct a timestamp with current year
    ts_str = f"{m.group('month')} {m.group('day')} {datetime.utcnow().year} {m.group('time')}"
    try:
        ts = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S").isoformat() + "Z"
    except:
        ts = None
    return {
        "timestamp": ts,
        "event_type": "auth",
        "action": "login",
        "user_id": m.group("user"),
        "host": m.group("host"),
        "src_ip": m.group("src_ip"),
        "src_port": int(m.group("src_port")),
        "status": "success" if m.group("result")=="Accepted" else "failure",
        "raw": line.strip()
    }

def parse_nginx_line(line):
    m = NGINX_RE.search(line)
    if not m:
        return None
    # nginx timestamp is like: 01/Oct/2025:12:34:56 +0000
    ts_raw = m.group("ts")
    # try parse dd/Mon/YYYY:HH:MM:SS
    try:
        ts = parser.parse(ts_raw.split()[0]).isoformat() + "Z"
    except:
        ts = None
    user = m.group("user") if m.group("user") != "-" else None
    return {
        "timestamp": ts,
        "event_type": "web",
        "action": m.group("method"),
        "resource": m.group("resource"),
        "user_id": user,
        "src_ip": m.group("src_ip"),
        "status": m.group("status"),
        "bytes": int(m.group("bytes")),
        "raw": line.strip()
    }

def parse_firewall_line(line):
    m = FW_RE.search(line)
    if not m:
        return None
    ts = None
    try:
        ts = datetime.strptime(f"{m.group('ts')} {datetime.utcnow().year}", "%b %d %H:%M:%S %Y").isoformat() + "Z"
    except:
        ts = None
    return {
        "timestamp": ts,
        "event_type": "network",
        "action": m.group("action"),
        "host": m.group("host"),
        "src_ip": m.group("src_ip"),
        "src_port": int(m.group("src_port")),
        "dst_ip": m.group("dst_ip"),
        "dst_port": int(m.group("dst_port")),
        "raw": line.strip()
    }

def parse_windows_json(line):
    try:
        j = json.loads(line)
        return {
            "timestamp": j.get("TimeCreated"),
            "event_type": "sys",
            "action": "windows_event",
            "host": j.get("Host"),
            "user_id": j.get("User"),
            "raw": line.strip(),
            "tags": [f"win_event_{j.get('EventID')}"]
        }
    except Exception:
        return None

def parse_endpoint_json(line):
    try:
        j = json.loads(line)
        return {
            "timestamp": j.get("timestamp"),
            "event_type": j.get("event_type") or "process",
            "user_id": j.get("user"),
            "host": j.get("host"),
            "process": j.get("process"),
            "resource": j.get("cmdline"),
            "raw": line.strip()
        }
    except:
        return None

def parse_file_audit_row(row):
    # row = [timestamp,user,path,action,bytes]
    ts, user, path, action, bytes_ = row
    return {
        "timestamp": ts,
        "event_type": "file",
        "action": action,
        "user_id": user,
        "resource": path,
        "bytes": int(bytes_) if bytes_ else 0,
        "raw": ",".join(row)
    }

def process_all(raw_dir=RAW_DIR, out_file=OUT_FILE):
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