"""Small Ollama HTTP client."""

from __future__ import annotations

from typing import Optional

import requests


class OllamaClient:
    def __init__(self, host: str = "http://127.0.0.1:11434", model: str = "phi3:mini", timeout: int = 60) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.last_error: str | None = None

    def is_available(self) -> bool:
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=5)
            self.last_error = None if response.ok else f"HTTP {response.status_code}: {response.text[:200]}"
            return response.ok
        except requests.RequestException as exc:
            self.last_error = str(exc)
            return False

    def list_models(self) -> list[str]:
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=5)
            response.raise_for_status()
            self.last_error = None
            return [str(item.get("name") or item.get("model")) for item in response.json().get("models", [])]
        except requests.RequestException as exc:
            self.last_error = str(exc)
            return []

    def has_model(self, model: str | None = None) -> bool:
        wanted = model or self.model
        models = set(self.list_models())
        return wanted in models

    def generate(self, prompt: str, json_format: bool = False) -> Optional[str]:
        payload = {"model": self.model, "prompt": prompt, "stream": False}
        if json_format:
            payload["format"] = "json"
        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            self.last_error = None
            return str(data.get("response", "")).strip()
        except requests.RequestException as exc:
            response = getattr(exc, "response", None)
            if response is not None:
                self.last_error = f"HTTP {response.status_code}: {response.text[:300]}"
            else:
                self.last_error = str(exc)
            return None
