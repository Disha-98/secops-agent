import json, os
from fastapi import FastAPI
from mcp_servers.common import ReputationRequest

app = FastAPI(title="TI-MCP")

# Resolve data path relative to repo root so it works no matter where you run from
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # -> secops-agent/
TI_PATH = os.path.join(BASE_DIR, "data", "ti_reputation.json")

def load_ti(path: str):
    try:
        print(f"[TI] Loading: {path}")
        if not os.path.exists(path):
            raise FileNotFoundError(f"No such file: {path}")
        # Read raw text to detect empties/BOMs etc.
        with open(path, "rb") as fb:
            raw = fb.read()
            print(f"[TI] Size: {len(raw)} bytes")
        text = raw.decode("utf-8-sig").strip()  # handle UTF-8 w/ BOM if present
        if not text:
            raise ValueError("TI file is empty")
        return json.loads(text)
    except Exception as e:
        print(f"[TI] WARNING: {e}. Using fallback empty TI DB.")
        return {"ips": {}, "hashes": {}}

TI = load_ti(TI_PATH)

@app.post("/tools/reputation")
def reputation(req: ReputationRequest):
    ip_info = TI.get("ips", {}).get(req.ioc)
    if ip_info:
        return {
            "type": "ip", "ioc": req.ioc,
            "verdict": ip_info.get("verdict", "unknown"),
            "sources": ip_info.get("sources", [])
        }
    hash_info = TI.get("hashes", {}).get(req.ioc)
    if hash_info:
        return {
            "type": "hash", "ioc": req.ioc,
            "verdict": hash_info.get("verdict", "unknown"),
            "sources": hash_info.get("sources", [])
        }
    return {"type": "unknown", "ioc": req.ioc, "verdict": "unknown", "sources": []}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7002)
