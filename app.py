"""HelpBot - LLM help-desk assistant (Flask + Ollama).

INTENTIONALLY VULNERABLE training application for Capstone Project 5.
Run only in an isolated lab environment.
"""
import os

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")


def ask_llm(user_message):
    # VULN (LLM01): user text is sent to the model as-is - no validation, length limit or injection filtering
    payload = {"model": MODEL, "prompt": user_message, "stream": False}
    resp = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=60)
    resp.raise_for_status()
    return resp.json()["response"]


@app.route("/chat", methods=["POST"])
def chat():
    # VULN: no authentication or rate limiting on the endpoint
    data = request.get_json(silent=True) or {}
    reply = ask_llm(data.get("message", ""))
    # VULN (LLM05): raw model output is returned to the client unmodified
    return jsonify({"response": reply})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
