import argparse, json, os
from rich import print
from agent.playbooks.triage_anomaly import TriagePlaybook

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", required=True, help="Path to alerts.jsonl")
    ap.add_argument("--case_dir", default="cases", help="Directory to save case JSONs")
    args = ap.parse_args()

    os.makedirs(args.case_dir, exist_ok=True)
    pb = TriagePlaybook()

    with open(args.alerts) as f:
        for line in f:
            alert = json.loads(line)
            case = pb.run(alert)
            cid = case["id"]
            with open(os.path.join(args.case_dir, f"{cid}.json"), "w") as out:
                json.dump(case, out, indent=2)
            print(f"[bold green]Created[/] {cid} severity={case['severity']}")
