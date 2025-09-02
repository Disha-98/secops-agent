\# SecOps Agent — MCP + Agentic Playbook (from scratch)



AI-driven SecOps lab: generate synthetic logs → detect anomalies → run an agentic triage playbook via MCP-style tool servers (SIEM/TI/SOAR) → open shadow cases.



\## 0) Prereqs

\- Python 3.10+

\- (Optional) Docker Desktop (for OpenSearch stack)

\- curl (or PowerShell `Invoke-RestMethod` on Windows)



\## 1) Setup

```bash

cd secops-agent

python -m venv .venv

\# macOS/Linux

source .venv/bin/activate

\# Windows (PowerShell)

. .\\.venv\\Scripts\\Activate.ps1



pip install --upgrade pip

pip install -r requirements.txt



