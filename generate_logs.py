#!/usr/bin/env python3
"""
generate_logs.py
Generates multiple raw log sources using Faker for a realistic multi-source dataset.
Usage:
  python generate_logs.py --count 2000
"""
import argparse, random, os, json, csv, uuid
from faker import Faker
from datetime import datetime, timedelta

fake = Faker()
random.seed(42)
Faker.seed(42)

HOSTS = [f"host-{i}" for i in range(1,8)]
USERS = [fake.user_name() for _ in range(20)]
ROLES = ["engineering","finance","hr","it","sales","exec"]

def times(start, n, max_seconds_back=7*24*3600):
    base = datetime.utcnow()
    for _ in range(n):
        delta = random.randint(0, max_seconds_back)
        yield (base - timedelta(seconds=delta)).strftime("%b %d %H:%M:%S")  # for syslog like

def make_auth_line(ts, host, user, src_ip, accepted=True):
    # e.g. "Oct  1 12:34:56 host sshd[123]: Accepted password for alice from 1.2.3.4 port 51234 ssh2"
    pid = random.randint(1000,99999)
    res = "Accepted" if accepted else "Failed"
    port = random.randint(1024,65000)
    return f"{ts} {host} sshd[{pid}]: {res} password for {user} from {src_ip} port {port} ssh2\n"

def make_nginx_line(ip, user, ts_common, method, resource, status, bytes_sent, ref="-", ua="-", host="example.com"):
    # combined log style: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'
    request = f'{method} {resource} HTTP/1.1'
    user_field = user if random.random() < 0.2 else "-"  # logged user sometimes '-'
    return f'{ip} - {user_field} [{ts_common}] "{request}" {status} {bytes_sent} "{ref}" "{ua}"\n'

def make_firewall_line(ts, host, action, src_ip, dst_ip, src_port, dst_port, proto="TCP"):
    # simple syslog-like firewall line
    return f"{ts} {host} FIREWALL: {action} proto={proto} src={src_ip}:{src_port} dst={dst_ip}:{dst_port}\n"

def make_windows_event(ev_time, host, user, ev_id, level, message):
    return json.dumps({
        "TimeCreated": ev_time.isoformat() + "Z",
        "Host": host,
        "User": user,
        "EventID": ev_id,
        "Level": level,
        "Message": message
    })+"\n"

def make_file_audit_row(ts_iso, user, path, action, bytes_):
    return [ts_iso, user, path, action, bytes_]

def make_endpoint_proc(ts_iso, user, host, process, cmdline, event_type):
    return json.dumps({
        "timestamp": ts_iso,
        "user": user,
        "host": host,
        "process": process,
        "cmdline": cmdline,
        "event_type": event_type
    }) + "\n"

def random_ip(private=False):
    if private:
        return random.choice(["10.0.0."+str(random.randint(2,250)), "192.168.1."+str(random.randint(2,250))])
    return fake.ipv4_public()

def main(count=2000, outdir="data/raw"):
    os.makedirs(outdir, exist_ok=True)
    # auth.log
    with open(os.path.join(outdir,"auth.log"), "w") as fa, \
         open(os.path.join(outdir,"nginx_access.log"), "w") as fn, \
         open(os.path.join(outdir,"firewall.log"), "w") as ff, \
         open(os.path.join(outdir,"windows_events.jsonl"), "w") as fw, \
         open(os.path.join(outdir,"file_audit.csv"), "w", newline='') as fcsv, \
         open(os.path.join(outdir,"endpoint_proc.jsonl"), "w") as fe:
        csvw = csv.writer(fcsv)
        csvw.writerow(["timestamp","user","path","action","bytes"])
        # generate times
        time_list_syslog = list(times(datetime.utcnow(), count))
        for i in range(count):
            # common fields
            host = random.choice(HOSTS)
            user = random.choice(USERS)
            role = random.choice(ROLES)
            # auth log (20% failed)
            accepted = random.random() > 0.15
            fa.write(make_auth_line(time_list_syslog[i], host, user, random_ip(), accepted))
            # nginx log
            ts_common = (datetime.utcnow() - timedelta(seconds=random.randint(0,7*24*3600))).strftime("%d/%b/%Y:%H:%M:%S +0000")
            method = random.choice(["GET","POST","PUT"])
            resource = random.choice(["/index.html","/api/login","/download/report.pdf","/assets/img.png","/upload"])
            status = random.choice([200,200,200,404,500,302])
            fn.write(make_nginx_line(random_ip(), user, ts_common, method, resource, status, random.randint(100,5000),
                                     ua=fake.user_agent()))
            # firewall lines (some denies)
            action = random.choice(["ALLOW","DENY","ALLOW","ALLOW"])
            ff.write(make_firewall_line(time_list_syslog[i], host, action, random_ip(), random_ip(), random.randint(1024,65000), random.randint(1,65535)))
            # windows events occasionally
            if random.random() < 0.2:
                ev_time = datetime.utcnow() - timedelta(seconds=random.randint(0,7*24*3600))
                ev_id = random.choice([4624,4625,7045,4688])
                level = random.choice(["Information","Warning","Error"])
                fw.write(make_windows_event(ev_time, host, user, ev_id, level, f"Sample message {uuid.uuid4()}"))
            # file audit rows
            if random.random() < 0.3:
                path = random.choice(["/shared/finance/q1.xlsx","/home/user/secrets.txt","/shared/hr/payroll.csv","/tmp/test.bin"])
                action = random.choice(["READ","WRITE","DELETE","DOWNLOAD"])
                bytes_ = random.randint(0,5_000_000)
                csvw.writerow(make_file_audit_row((datetime.utcnow() - timedelta(seconds=random.randint(0,7*24*3600))).isoformat()+"Z", user, path, action, bytes_))
            # endpoint process
            if random.random() < 0.2:
                ts_iso = (datetime.utcnow() - timedelta(seconds=random.randint(0,7*24*3600))).isoformat()+"Z"
                proc = random.choice(["powershell.exe","bash","python","curl","scp","cmd.exe"])
                cmd = f"{proc} -c 'do something {random.randint(1,100)}'"
                fe.write(make_endpoint_proc(ts_iso, user, host, proc, cmd, "process_start"))
    print("Wrote synthetic raw logs to", outdir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=2000, help="number of events to generate")
    parser.add_argument("--outdir", default="data/raw")
    args = parser.parse_args()
    main(args.count, args.outdir)
