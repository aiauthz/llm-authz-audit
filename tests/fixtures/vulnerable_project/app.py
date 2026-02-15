"""Intentionally vulnerable LLM application for testing."""

from fastapi import FastAPI

app = FastAPI()

# SEC001: Hardcoded OpenAI API key
OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"

# SEC002: Hardcoded Anthropic API key
ANTHROPIC_KEY = "sk-ant-abcdefghijklmnopqrstuvwxyz1234567890"

# EP001: Unauthenticated chat endpoint
@app.post("/chat")
async def chat(message: str):
    return {"response": "hello"}

# EP001: Unauthenticated completions endpoint
@app.post("/v1/completions")
async def completions(prompt: str):
    return {"text": "generated"}
