# HelpBot — vulnerable LLM help-desk assistant

HelpBot is a small, **intentionally vulnerable** AI application (Flask + Ollama) used as the target of
Capstone Project 5 — *Build a DevSecOps Pipeline with AI-Specific Security Gates*.
Run it only in an isolated lab environment.

## Run locally (Windows PowerShell)
```powershell
python -m venv .venv; .venv\Scripts\Activate.ps1; pip install -r requirements.txt
python app.py
```
Then `POST http://127.0.0.1:5000/chat` with `{"message": "..."}` (requires a local Ollama server).
