import re
from fastapi import FastAPI
from mcp_servers.common import LogEvent, QueryRequest

app = FastAPI(title="SIEM-MCP")

# Location of synthetic log file
LOG_PATH = "data/sample_logs.jsonl"

def load_events():
    with open(LOG_PATH) as f:
        for line in f:
            yield LogEvent.model_validate_json(line)

@app.post("/tools/query_logs")
def query_logs(req: QueryRequest):
    # Parse query like: user:alice src:1.2.3.4 app:ssh outcome:failure
    terms = dict([tuple(t.split(":", 1)) for t in re.findall(r"(\w+:[^\s]+)", req.query)])
    out = []
    for ev in load_events():
        ok = True
        for k, v in terms.items():
            if k == "user" and ev.user != v: ok = False
            if k == "src" and ev.src_ip != v: ok = False
            if k == "app" and ev.app != v: ok = False
            if k == "outcome" and ev.outcome != v: ok = False
        if ok:
            out.append(ev)
        if len(out) > 5000:
            break
    return {"events": [e.model_dump() for e in out]}

@app.post("/tools/recent_activity")
def recent_activity(req: QueryRequest):
    # For clarity, alias to query_logs
    return query_logs(req)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7001)
