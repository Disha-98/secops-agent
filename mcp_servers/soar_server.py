from datetime import datetime
from fastapi import FastAPI
from mcp_servers.common import Case
from typing import Dict

app = FastAPI(title="SOAR-MCP")

# In-memory case store
CASES: Dict[str, Case] = {}

@app.post("/tools/create_case")
def create_case(case: Case):
    CASES[case.id] = case
    return {"ok": True, "id": case.id}

@app.post("/tools/add_note")
def add_note(cid: str, text: str):
    if cid not in CASES:
        return {"ok": False, "error": "case not found"}
    CASES[cid].notes.append(text)
    return {"ok": True, "notes": len(CASES[cid].notes)}

@app.post("/tools/isolate_host_dryrun")
def isolate_host_dryrun(host: str):
    # Shadow mode only – no real action
    return {"ok": True, "action": "isolate", "host": host, "executed": False}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7003)
