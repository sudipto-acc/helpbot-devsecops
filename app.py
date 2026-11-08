"""HelpBot - LLM help-desk assistant (Flask + Ollama).

INTENTIONALLY VULNERABLE training application for Capstone Project 5.
Run only in an isolated lab environment.
"""
import ast
import operator
import os
import re

import requests
from flask import Flask, jsonify, request

from config import LLM_API_KEY, get_system_prompt

app = Flask(__name__)

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")

CALC_TOOL = re.compile(r"CALC:\s*([^\n]+)")
MAX_EXPRESSION_LENGTH = 100
# FIX 3: arithmetic-only evaluator replaces eval() - anything other than numbers and these operators is rejected
OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _evaluate(node):
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in OPERATORS:
        left, right = _evaluate(node.left), _evaluate(node.right)
        if isinstance(node.op, ast.Pow) and (abs(left) > 1_000_000 or abs(right) > 100):
            raise ValueError("exponent too large")
        return OPERATORS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in OPERATORS:
        return OPERATORS[type(node.op)](_evaluate(node.operand))
    raise ValueError("only basic arithmetic is allowed")


def ask_llm(user_message):
    # VULN (LLM01): user text is sent to the model as-is - no validation, length limit or injection filtering
    payload = {"model": MODEL, "system": get_system_prompt(), "prompt": user_message, "stream": False}
    headers = {"Authorization": f"Bearer {LLM_API_KEY}"} if LLM_API_KEY else {}
    resp = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.json()["response"]


def run_calculator(expression):
    if len(expression) > MAX_EXPRESSION_LENGTH:
        return "error: expression too long"
    try:
        return _evaluate(ast.parse(expression, mode="eval").body)
    except (ValueError, SyntaxError, ZeroDivisionError, OverflowError):
        return "error: unsupported expression"


@app.route("/chat", methods=["POST"])
def chat():
    # VULN: no authentication or rate limiting on the endpoint
    data = request.get_json(silent=True) or {}
    reply = ask_llm(data.get("message", ""))
    tool_call = CALC_TOOL.search(reply)
    if tool_call:
        reply += f"\n\n[calculator] {run_calculator(tool_call.group(1).strip())}"
    # VULN (LLM05): raw model output is returned to the client unmodified
    return jsonify({"response": reply})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
