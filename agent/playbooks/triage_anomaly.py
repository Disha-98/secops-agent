import json
import httpx

class TriagePlaybook:
    """
    Enrich → Correlate → Decide → Shadow Action
    Talks to three MCP-style services:
      - SIEM:   http://localhost:7001
      - TI:     http://localhost:7002
      - SOAR:   http://localhost:7003
    """

    def __init__(self,
                 siem_url: str = "http://localhost:7001",
                 ti_url: str = "http://localhost:7002",
                 soar_url: str = "http://localhost:7003"):
        self.siem = siem_url
        self.ti = ti_url
        self.soar = soar_url

    # ---------- Playbook steps ----------

    def enrich(self, alert: dict) -> dict:
        """Gather recent activity for user & src_ip + TI reputation."""
        q_user = {"query": f"user:{alert['user']}", "window": "7d"}
        q_src  = {"query": f"src:{alert['src_ip']}", "window": "7d"}

        with httpx.Client(timeout=30) as c:
            u = c.post(f"{self.siem}/tools/recent_activity", json=q_user).json()
            s = c.post(f"{self.siem}/tools/recent_activity", json=q_src).json()
            rep = c.post(f"{self.ti}/tools/reputation", json={"ioc": alert["src_ip"]}).json()

        return {
            "user_activity": u.get("events", []),
            "src_activity":  s.get("events", []),
            "reputation":    rep
        }

    def decision(self, alert: dict, ctx: dict) -> tuple[str, dict]:
        """Policy: anomaly score + TI + port probe heuristic."""
        sev = "low"
        verdict = ctx["reputation"].get("verdict")
        score = alert.get("score", 0.0)

        # Count port probes from this src in the context
        port_probes = sum(1 for e in ctx.get("src_activity", []) if e.get("action") == "port_probe")

        # HIGH if malicious OR very high score OR many probes
        if verdict == "malicious" or score > 0.8 or port_probes >= 20:
            sev = "high"
        # MEDIUM if somewhat suspicious
        elif score > 0.6 or port_probes >= 10:
            sev = "medium"

        action = {"kind": "none"}
        if sev == "high":
            action = {"kind": "propose_isolation", "host": alert["src_ip"]}
        return sev, action

    def case_payload(self, alert: dict, ctx: dict, sev: str, action: dict) -> dict:
        """Build a SOAR case object compatible with our /tools/create_case schema."""
        title = f"Anomaly triage for {alert['user']} from {alert['src_ip']} (score={alert['score']:.2f})"
        notes = [
            "Playbook: enrich → correlate → decision (shadow mode)",
            f"TI verdict: {ctx['reputation'].get('verdict')}",
            f"User events (sample): {json.dumps(ctx['user_activity'][:5])}",
            f"Port probes counted: {sum(1 for e in ctx.get('src_activity', []) if e.get('action') == 'port_probe')}"
        ]
        return {
            "id": alert["alert_id"].replace("ALERT", "CASE"),
            "title": title,
            "severity": sev,
            "created_ts": alert.get("created_ts", ""),
            "artifacts": {
                "alert": alert,
                "context_summary": {
                    "user_events": len(ctx["user_activity"]),
                    "src_events": len(ctx["src_activity"])
                },
                "action": action
            },
            "notes": notes
        }

    def run(self, alert: dict) -> dict:
        """Execute full playbook and persist a SOAR case (shadow actions only)."""
        ctx = self.enrich(alert)
        sev, action = self.decision(alert, ctx)
        payload = self.case_payload(alert, ctx, sev, action)

        with httpx.Client(timeout=30) as c:
            # Create case with JSON body
            c.post(f"{self.soar}/tools/create_case", json=payload)

            # Shadow action (query params)
            if action.get("kind") == "propose_isolation":
                c.post(f"{self.soar}/tools/isolate_host_dryrun", params={"host": action["host"]})

            # Add a recommendation note (query params for both fields)
            c.post(f"{self.soar}/tools/add_note",
                   params={"cid": payload["id"], "text": f"Recommended action: {action}"})

        return payload
