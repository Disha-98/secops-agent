"""
Simple evaluation helper.

Usage:
  python eval/metrics.py --alerts alerts.jsonl --labels labels.jsonl --k 50
  # Optional: include agent cases to compare against baseline
  python eval/metrics.py --alerts alerts.jsonl --labels labels.jsonl --cases_dir cases --k 50

Inputs:
- alerts.jsonl : lines of {"alert_id","score",...}
- labels.jsonl : lines of {"alert_id","label"} where label in {0,1} (1=true positive)
- cases_dir    : directory containing CASE-*.json produced by agent (optional)

Metrics:
- Baseline precision@K (score descending)
- Agent precision@K (treats severity in {high,medium} as positive), if cases provided
"""

import argparse, json, os
from collections import defaultdict

def load_jsonl(path):
    rows = []
    with open(path) as f:
        for line in f:
            rows.append(json.loads(line))
    return rows

def load_cases(cases_dir):
    cases = {}
    if not os.path.isdir(cases_dir):
        return cases
    for fn in os.listdir(cases_dir):
        if not fn.endswith(".json"):
            continue
        p = os.path.join(cases_dir, fn)
        try:
            obj = json.load(open(p))
            # Map back to alert id (CASE-... -> ALERT-...)
            aid = obj.get("id","").replace("CASE", "ALERT")
            cases[aid] = obj
        except Exception:
            pass
    return cases

def precision_at_k(pred_ids, labels_map, k):
    take = pred_ids[:max(1, k)]
    tp = sum(1 for aid in take if labels_map.get(aid, 0) == 1)
    return tp / len(take)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--cases_dir", default=None)
    ap.add_argument("--k", type=int, default=50)
    args = ap.parse_args()

    alerts = load_jsonl(args.alerts)
    labels = load_jsonl(args.labels)
    labels_map = {r["alert_id"]: int(r["label"]) for r in labels}

    # ---- Baseline: rank by anomaly score (desc)
    ranked_by_score = sorted(alerts, key=lambda a: a.get("score", 0.0), reverse=True)
    baseline_ids = [a["alert_id"] for a in ranked_by_score]
    p_at_k_baseline = precision_at_k(baseline_ids, labels_map, args.k)

    print(f"Baseline precision@{args.k} (score): {p_at_k_baseline:.3f}")

    # ---- Agent-based (optional): treat medium/high as positives
    if args.cases_dir:
        cases = load_cases(args.cases_dir)
        # If we have cases for many alerts, rank by severity first (high>medium>low), then score
        sev_rank = {"high": 2, "medium": 1, "low": 0, "critical": 3}
        def agent_key(a):
            case = cases.get(a["alert_id"], {})
            sev = case.get("severity", "low")
            return (sev_rank.get(sev, 0), a.get("score", 0.0))  # tuple sorts by severity then score
        ranked_agent = sorted(alerts, key=agent_key, reverse=True)
        agent_ids = [a["alert_id"] for a in ranked_agent]
        p_at_k_agent = precision_at_k(agent_ids, labels_map, args.k)
        print(f"Agent precision@{args.k} (severity→score): {p_at_k_agent:.3f}")

        # Also report auto-closure rate (low severity proportion)
        lows = sum(1 for a in alerts if cases.get(a["alert_id"], {}).get("severity") == "low")
        print(f"Auto-closure rate (low severity): {lows/len(alerts):.3f}")
