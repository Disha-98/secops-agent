from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class LogEvent(BaseModel):
    ts: str
    src_ip: str
    user: str
    app: str
    action: str
    country: str
    outcome: str

class QueryRequest(BaseModel):
    query: str               # e.g., "user:alice src:1.2.3.4 app:ssh outcome:failure"
    window: Optional[str] = "7d"

class ReputationRequest(BaseModel):
    ioc: str                 # IP or hash

class Case(BaseModel):
    id: str
    title: str
    severity: str            # low | medium | high | critical
    created_ts: Optional[str] = ""
    artifacts: Dict[str, Any]
    notes: List[str] = []
