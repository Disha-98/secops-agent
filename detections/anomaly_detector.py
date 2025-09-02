import argparse, json
import pandas as pd
from sklearn.ensemble import IsolationForest

# Input: JSONL events -> simple daily aggregates per (src_ip,user) -> anomaly scores -> alerts.jsonl
# Event schema: {"ts","src_ip","user","app","action","country","outcome"}

def load_jsonl(path):
    rows = []
    with open(path) as f:
        for line in f:
            rows.append(json.loads(line))
    return pd.DataFrame(rows)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Path to sample_logs.jsonl")
    ap.add_argument("--out", dest="outp", required=True, help="Path to write alerts.jsonl")
    args = ap.parse_args()

    df = load_jsonl(args.inp)
    if df.empty:
        raise SystemExit("No events found. Generate data first.")

    # Daily aggregation per (src_ip, user)
    df["day"] = df["ts"].str[:10]
    agg = df.groupby(["day", "src_ip", "user"]).agg(
        events=("action", "count"),
        failures=("outcome", lambda s: (s == "failure").sum()),
        apps=("app", pd.Series.nunique),
        countries=("country", pd.Series.nunique),
        port_probes=("action", lambda s: (s == "port_probe").sum())
    ).reset_index()

    feats = agg[["events", "failures", "apps", "countries", "port_probes"]]

    model = IsolationForest(contamination=0.02, random_state=42)
    model.fit(feats)
    scores = -model.decision_function(feats)  # higher = more anomalous
    agg["anom_score"] = scores

    alerts = []
    top = agg.sort_values("anom_score", ascending=False).head(100)
    for _, r in top.iterrows():
        alerts.append({
            "alert_id": f"ALERT-{r['day']}-{r['src_ip']}-{r['user']}",
            "src_ip": r["src_ip"],
            "user": r["user"],
            "score": float(r["anom_score"]),
            "artifacts": {
                "window_day": r["day"],
                "events": int(r["events"]),
                "failures": int(r["failures"]),
                "apps": int(r["apps"]),
                "countries": int(r["countries"]),
                "port_probes": int(r["port_probes"])
            },
            "type": "anomaly.iforest"
        })

    with open(args.outp, "w") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")
    print(f"wrote {len(alerts)} alerts → {args.outp}")
