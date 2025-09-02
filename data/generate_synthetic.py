import argparse, json, random, uuid
from datetime import datetime, timedelta
from dateutil.tz import tzutc

USERS = ["alice","bob","carol","dave","eve"]
APPS = ["vpn","vpn","okta","okta","rdp","ssh","share"]
COUNTRIES = ["US","US","US","DE","IN","CN","BR","FR"]

# Simple log schema per line (JSONL):
# { ts, src_ip, user, app, action, country, outcome }

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def gen_normal_event(t0):
    return {
        "ts": (t0 + timedelta(seconds=random.randint(0, 86400))).isoformat(),
        "src_ip": rand_ip(),
        "user": random.choice(USERS),
        "app": random.choice(APPS),
        "action": random.choice(["login","logout","file_access","port_probe","policy_check"]),
        "country": random.choice(COUNTRIES[:3]),  # mostly domestic
        "outcome": random.choice(["success","failure","failure"])
    }

# Plant anomalies: geo-rare success after failures, burst probes, new country
def gen_anomaly(t0):
    kind = random.choice(["rare_geo_success","burst_failures","port_scan_burst"])
    base_ip = rand_ip()
    user = random.choice(USERS)
    records = []
    if kind == "rare_geo_success":
        for _ in range(6):
            records.append({
                "ts": (t0 + timedelta(minutes=random.randint(0, 120))).isoformat(),
                "src_ip": base_ip,
                "user": user,
                "app": "vpn",
                "action": "login",
                "country": random.choice(["CN","RU","BR","NG"]),
                "outcome": "failure"
            })
        records.append({
            "ts": (t0 + timedelta(minutes=130)).isoformat(),
            "src_ip": base_ip,
            "user": user,
            "app": "vpn",
            "action": "login",
            "country": random.choice(["CN","RU","BR","NG"]),
            "outcome": "success"
        })
    elif kind == "burst_failures":
        for _ in range(20):
            records.append({
                "ts": (t0 + timedelta(seconds=random.randint(0, 600))).isoformat(),
                "src_ip": base_ip,
                "user": user,
                "app": "okta",
                "action": "login",
                "country": "US",
                "outcome": "failure"
            })
    else:  # port_scan_burst
        for p in range(20):
            records.append({
                "ts": (t0 + timedelta(seconds=p*3)).isoformat(),
                "src_ip": base_ip,
                "user": user,
                "app": "ssh",
                "action": "port_probe",
                "country": "US",
                "outcome": "failure"
            })
    return records

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--days", type=int, default=1)
    ap.add_argument("--anomalies", type=int, default=8)
    args = ap.parse_args()

    tstart = datetime.now(tzutc()) - timedelta(days=args.days)
    data = []
    for d in range(args.days):
        day0 = tstart + timedelta(days=d)
        # Normal traffic
        for _ in range(3000):
            data.append(gen_normal_event(day0))
        # Anomalies
        for _ in range(args.anomalies):
            data.extend(gen_anomaly(day0))

    with open(args.out, "w") as f:
        for rec in sorted(data, key=lambda r: r["ts"]):
            f.write(json.dumps(rec) + "\n")
    print(f"wrote {len(data)} events → {args.out}")
