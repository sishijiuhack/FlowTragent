"""Small Ollama HTTP client."""

from __future__ import annotations

from typing import Optional

import requests


class OllamaClient:
    def __init__(self, host: str = "http://127.0.0.1:11434", model: str = "phi3:mini", timeout: int = 60) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=5)
            return response.ok
        except requests.RequestException:
            return False

    def generate(self, prompt: str) -> Optional[str]:
        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return str(data.get("response", "")).strip()
        except requests.RequestException:
            return None

