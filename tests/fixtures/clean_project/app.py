"""Clean LLM application — no findings expected."""

import os

from fastapi import Depends, FastAPI

app = FastAPI()

# Secrets loaded from environment
OPENAI_KEY = os.environ["OPENAI_API_KEY"]


def get_current_user():
    """Auth dependency."""
    pass


@app.post("/chat")
async def chat(message: str, user=Depends(get_current_user)):
    return {"response": "hello"}
