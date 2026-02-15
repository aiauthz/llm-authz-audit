"""LLM provider protocol and adapters for OpenAI and Anthropic."""

from __future__ import annotations

from typing import Protocol


class LLMProvider(Protocol):
    """Protocol for LLM providers."""

    def complete(self, prompt: str, system: str = "") -> str:
        """Send a prompt and return the response text."""
        ...


class AnthropicProvider:
    """Anthropic Claude adapter."""

    def __init__(self, model: str = "claude-sonnet-4-5-20250929") -> None:
        try:
            import anthropic
        except ImportError:
            raise ImportError("Install AI dependencies: pip install llm-authz-audit[ai]")
        self.client = anthropic.Anthropic()
        self.model = model

    def complete(self, prompt: str, system: str = "") -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system or "You are a security expert analyzing LLM application code.",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text


class OpenAIProvider:
    """OpenAI adapter."""

    def __init__(self, model: str = "gpt-4o") -> None:
        try:
            import openai
        except ImportError:
            raise ImportError("Install AI dependencies: pip install llm-authz-audit[ai]")
        self.client = openai.OpenAI()
        self.model = model

    def complete(self, prompt: str, system: str = "") -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=4096,
        )
        return response.choices[0].message.content or ""


def get_provider(provider_name: str, model: str | None = None) -> LLMProvider:
    """Factory to create a provider by name."""
    if provider_name == "anthropic":
        return AnthropicProvider(model=model or "claude-sonnet-4-5-20250929")
    elif provider_name == "openai":
        return OpenAIProvider(model=model or "gpt-4o")
    else:
        raise ValueError(f"Unknown provider: {provider_name}. Supported: anthropic, openai")
