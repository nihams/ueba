import argparse
import random
import os
import json
import csv
from faker import Faker
from datetime import datetime, timedelta

# --- Configuration: Scaled for Hackathon ---
NUM_DEVELOPERS = 80
NUM_SALES = 100
NUM_ADMINS = 19
TOTAL_USERS = NUM_DEVELOPERS + NUM_SALES + NUM_ADMINS + 1 # +1 for the attacker

HOSTS = [f"host-{i}" for i in range(1, 15)]
DEVELOPER_HOSTS = HOSTS[:5]
ADMIN_HOSTS = HOSTS
SALES_HOSTS = HOSTS[10:]

# Common web destinations to make traffic look realistic
COMMON_DOMAINS = {
    "Search": ["google.com", "bing.com"],
    "Social Media": ["linkedin.com", "twitter.com"],
    "News": ["cnn.com", "bbc.com", "nytimes.com"],
    "Developer Tools": ["github.com", "stackoverflow.com", "gitlab.com"],
    "Cloud Services": ["aws.amazon.com", "office.com", "salesforce.com"],
    "File Sharing": ["dropbox.com", "mega.nz", "wetransfer.com"], # For exfil
    "Text & Media Sharing": ["pastebin.com", "ghostbin.co"] # For exfil
}
RARE_C2_DOMAIN = "upd.security-analytics.net" # Attacker Command & Control

fake = Faker()

# --- Log Formatting Functions (Includes NEW web_proxy_log) ---

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

def make_web_proxy_log(ts, user, host, src_ip, dst_hostname, http_method, bytes_out, user_agent, url_category, status_code=200):
    # This is the NEW function to generate web traffic logs
    dst_ip = fake.ipv4_public() # Simulate resolving the hostname
    return json.dumps({
        "timestamp": ts.isoformat() + "Z",
        "event_type": "web",
        "user_id": user,
        "host": host,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_hostname": dst_hostname,
        "http_method": http_method,
        "bytes_out": bytes_out,
        "bytes_in": random.randint(100, 5000),
        "user_agent": user_agent,
        "url_category": url_category,
        "status_code": status_code
    }) + "\n"

# --- Persona and Behavior Generation ---

def generate_personas():
    personas = []
    # Developers
    for i in range(NUM_DEVELOPERS):
        user = fake.user_name()
        personas.append({'user_id': user, 'role': 'developer', 'home_ip': fake.ipv4_public(), 'home_host': random.choice(DEVELOPER_HOSTS)})
    # Sales
    for i in range(NUM_SALES):
        user = fake.user_name()
        personas.append({'user_id': user, 'role': 'sales', 'home_ip': fake.ipv4_public(), 'home_host': random.choice(SALES_HOSTS)})
    # Admins
    for i in range(NUM_ADMINS):
        user = fake.user_name()
        personas.append({'user_id': user, 'role': 'admin', 'home_ip': fake.ipv4_public(), 'home_host': 'host-1'})
    
    # Add our specific attacker
    personas.append({'user_id': 'test_attacker', 'role': 'developer', 'home_ip': '198.51.100.99', 'home_host': 'host-7'})
    
    return personas

def generate_normal_activity(writers, persona, base_time):
    user = persona['user_id']
    role = persona['role']
    home_host = persona['home_host']
    home_ip = persona['home_ip']
    user_agent = fake.chrome()

    # Generic activity for all roles
    if random.random() < 0.5:
        writers['auth'].write(make_auth_line(base_time, home_host, user, home_ip, success=random.random() > 0.1))
    if random.random() < 0.8:
        category, domains = random.choice(list(COMMON_DOMAINS.items()))
        if role == 'developer' and category not in ["Developer Tools", "Search", "Cloud Services"]: return # Developers stick to their tools
        writers['web'].write(make_web_proxy_log(base_time, user, home_host, home_ip, random.choice(domains), 'GET', random.randint(100, 1000), user_agent, category))

    # Role-specific activity
    if role == 'developer':
        if random.random() < 0.3:
            writers['proc'].write(make_endpoint_proc(base_time, user, home_host, 'git', 'git pull origin main'))
        if random.random() < 0.1: # Pushing code
             writers['web'].write(make_web_proxy_log(base_time, user, home_host, home_ip, 'github.com', 'POST', random.randint(50000, 200000), user_agent, "Developer Tools"))

    elif role == 'admin':
         if random.random() < 0.4: # Admins log into many different servers
             target_host = random.choice(ADMIN_HOSTS)
             writers['auth'].write(make_auth_line(base_time, target_host, user, home_ip, success=True))

def generate_scripted_attack_chain(writers, persona, base_time):
    """Simulates a specific, multi-stage attack for the 'test_attacker' persona."""
    user = persona['user_id']
    host = persona['home_host']
    attacker_ip_impossible_travel = '5.188.10.225' # A known suspicious IP from another country

    print(f"Injecting ATTACK CHAIN for user '{user}' at {base_time}")

    # STAGE 1: Impossible Travel Login (Compromised Credential)
    ts_stage1 = base_time
    writers['auth'].write(make_auth_line(ts_stage1, host, user, attacker_ip_impossible_travel, success=True))

    # STAGE 2: Internal Discovery & Sensitive File Access
    ts_stage2 = base_time + timedelta(minutes=5)
    writers['proc'].write(make_endpoint_proc(ts_stage2, user, host, 'net.exe', 'net group "Domain Admins" /domain'))
    writers['file'].writerow(make_file_audit_row(ts_stage2, user, '/shared/research/project_x_blueprints.pdf', 'READ', 2048576))
    
    # STAGE 3: Command & Control (C2) Beaconing using PowerShell User-Agent
    ts_stage3 = base_time + timedelta(minutes=10)
    powershell_ua = "PowerShell/7.2"
    writers['web'].write(make_web_proxy_log(ts_stage3, user, host, "192.168.1.101", RARE_C2_DOMAIN, 'GET', 256, powershell_ua, "C2 Beacon"))
    
    # STAGE 4: Data Exfiltration via POST to Pastebin
    ts_stage4 = base_time + timedelta(minutes=15)
    writers['web'].write(make_web_proxy_log(ts_stage4, user, host, "192.168.1.101", 'pastebin.com', 'POST', 2048576, powershell_ua, "Text & Media Sharing"))


def main(count=10000, outdir="data/raw"):
    os.makedirs(outdir, exist_ok=True)
    
    files = {
        "auth": open(os.path.join(outdir, "auth.log"), "w"),
        "web": open(os.path.join(outdir, "web_proxy.jsonl"), "w"),
        "proc": open(os.path.join(outdir, "endpoint_proc.jsonl"), "w"),
        "file_csv": open(os.path.join(outdir, "file_audit.csv"), "w", newline='')
    }
    writers = {'file': csv.writer(files['file_csv']), **{k: v for k, v in files.items() if k != 'file_csv'}}
    writers['file'].writerow(["timestamp", "user", "path", "action", "bytes"])
    
    personas = generate_personas()
    start_time = datetime.utcnow() - timedelta(days=30)
    
    print(f"Generating ~{count} events for {len(personas)} users over a 30-day period...")

    # Inject the scripted attack chain ONCE at a random time
    attack_time = start_time + timedelta(seconds=random.randint(0, 30*24*3600))
    attacker_persona = next(p for p in personas if p['user_id'] == 'test_attacker')
    generate_scripted_attack_chain(writers, attacker_persona, attack_time)

    # Generate the rest of the normal traffic
    for i in range(count):
        persona = random.choice(personas)
        if persona['user_id'] == 'test_attacker': continue # Skip normal traffic for the attacker to make them stand out
        
        event_time = start_time + timedelta(seconds=random.randint(0, 30*24*3600))
        generate_normal_activity(writers, persona, event_time)

    for f in files.values():
        f.close()
        
    print(f"\n✅ Wrote enhanced synthetic logs to '{outdir}'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate realistic, scenario-based log data for UEBA.")
    parser.add_argument("--count", type=int, default=20000, help="Approximate number of normal events to generate.")
    parser.add_argument("--outdir", default="data/raw", help="Directory to save the raw log files.")
    args = parser.parse_args()
    main(args.count, args.outdir)

    
