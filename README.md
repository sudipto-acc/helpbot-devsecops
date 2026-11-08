# HelpBot — vulnerable LLM help-desk assistant

HelpBot is a small, **intentionally vulnerable** AI application (Flask + Ollama) used as the target of
Capstone Project 5 — *Build a DevSecOps Pipeline with AI-Specific Security Gates*.
Run it only in an isolated lab environment.

## Security pipeline
[`.github/workflows/security.yml`](.github/workflows/security.yml) runs four sequential security gates on
every push:

| Gate | Tool | Fails on |
|---|---|---|
| 1 | Bandit SAST — `bandit -r .` | any High severity finding (`eval`/`exec` escalated to High for this AI app) |
| 2 | Safety — `safety check -r requirements.txt` | any Critical or High CVE |
| 3 | Gitleaks — scans the pushed commit diff | any API key, password or token pattern |
| 4 | [`inject_scanner.py`](inject_scanner.py) | hardcoded system prompts or prompt-injection phrases in any `.py` file |

Design document, fail/fix results and screenshots: [docs/pipeline_design.md](docs/pipeline_design.md)

## Run locally (Windows PowerShell)
```powershell
python -m venv .venv; .venv\Scripts\Activate.ps1; pip install -r requirements.txt
$env:LLM_API_KEY = "<optional LLM gateway key>"
$env:HELPBOT_SYSTEM_PROMPT = "You are HelpBot, the IT help-desk assistant. For arithmetic reply with one line: CALC: <expression>"
python app.py
```
Then `POST http://127.0.0.1:5000/chat` with `{"message": "..."}` (requires a local Ollama server).

## Run the gates locally
```powershell
pip install bandit==1.9.4 safety==3.8.1
bandit -r . -x ./.venv
safety check -r requirements.txt
gitleaks git .          # https://github.com/gitleaks/gitleaks/releases
python inject_scanner.py
```
