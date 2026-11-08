"""HelpBot runtime configuration - secrets and prompts are injected via environment variables."""
import os

# FIX 1: API key is read from the environment / CI secret store instead of being hardcoded
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")


def get_system_prompt():
    # FIX 4: system prompt is deployment configuration, loaded from the environment at call time
    return os.environ.get("HELPBOT_SYSTEM_PROMPT", "")
