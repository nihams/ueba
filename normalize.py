#!/usr/bin/env python3
"""
normalize.py
Reads data/raw/* and writes data/normalized/events.jsonl using the canonical schema.
"""
import os, json, re
from dateutil import parser
from datetime import datetime
import csv

RAW_DIR = "data/raw"
OUT_DIR = "data/normalized"
os.makedirs(OUT_DIR, exist_ok=True)
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
    # AUTH
    authf = os.path.join(raw_dir, "auth.log")
    if os.path.exists(authf):
        with open(authf) as f:
            for line in f:
                p = parse_auth_line(line)
                if p: events.append(p)
    # nginx
    ngf = os.path.join(raw_dir, "nginx_access.log")
    if os.path.exists(ngf):
        with open(ngf) as f:
            for line in f:
                p = parse_nginx_line(line)
                if p: events.append(p)
    # firewall
    fwf = os.path.join(raw_dir, "firewall.log")
    if os.path.exists(fwf):
        with open(fwf) as f:
            for line in f:
                p = parse_firewall_line(line)
                if p: events.append(p)
    # windows events
    wwf = os.path.join(raw_dir, "windows_events.jsonl")
    if os.path.exists(wwf):
        with open(wwf) as f:
            for line in f:
                p = parse_windows_json(line)
                if p: events.append(p)
    # endpoint proc
    epf = os.path.join(raw_dir, "endpoint_proc.jsonl")
    if os.path.exists(epf):
        with open(epf) as f:
            for line in f:
                p = parse_endpoint_json(line)
                if p: events.append(p)
    # file audit CSV
    fc = os.path.join(raw_dir, "file_audit.csv")
    if os.path.exists(fc):
        with open(fc) as f:
            rdr = csv.reader(f)
            header = next(rdr, None)
            for row in rdr:
                p = parse_file_audit_row(row)
                if p: events.append(p)
    # write JSONL
    with open(out_file, "w") as out:
        for ev in events:
            # ensure timestamp normalized
            if ev.get("timestamp"):
                try:
                    ev["timestamp"] = iso_or_none(ev["timestamp"])
                except:
                    ev["timestamp"] = ev["timestamp"]
            out.write(json.dumps(ev) + "\n")
    print("Wrote normalized events:", out_file, "count:", len(events))

if __name__ == "__main__":
    process_all()
