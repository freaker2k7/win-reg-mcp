"""HTTP client for local Ollama chat, structured generation, and embeddings."""

from __future__ import annotations

import base64
import json
import logging
import math
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from win_reg_mcp.config import Settings

LOGGER = logging.getLogger(__name__)


class OllamaError(RuntimeError):
    """Raised when the configured local Ollama service cannot satisfy a request."""


class OllamaClient:
    """Use Ollama's local HTTP API without introducing a remote inference dependency."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _post(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Send a bounded JSON request to Ollama and preserve useful error details."""
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.settings.ollama_url}{endpoint}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.settings.ollama_timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OllamaError(f"Ollama request to {endpoint} failed: {exc}") from exc

    def check_available(self) -> None:
        """Verify the local daemon before an expensive full Registry scan begins."""
        request = urllib.request.Request(f"{self.settings.ollama_url}/api/tags", method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.settings.tool_timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OllamaError(
                f"Cannot reach Ollama at {self.settings.ollama_url}: {exc}. "
                "Start Ollama and pull the configured models first."
            ) from exc
        installed = {item.get("name", "") for item in payload.get("models", [])}
        expected = {
            self.settings.chat_model,
            self.settings.embedding_model,
        }
        missing = [model for model in expected if model not in installed]
        if missing:
            raise OllamaError(
                "Missing Ollama model(s): "
                + ", ".join(sorted(missing))
                + ". Pull them with `ollama pull MODEL` before starting the server."
            )

    def explain_registry_batch(self, records: list[dict[str, Any]]) -> list[str]:
        """Generate concise, cautious explanations for newly discovered Registry values."""
        if not records:
            return []
        system = (
            "You are a Windows Registry documentation specialist. Explain each supplied value in "
            "two to four useful sentences for a technical Windows administrator. "
            "for a technical Windows administrator. Never infer an undocumented purpose from "
            "the value name alone. When its behavior is uncertain, explicitly say so. Explain "
            "the setting's likely effect, scope, accepted data meaning when known, and caveats. "
            "Do not recommend changing it. Return only JSON: {items:[{id, explanation}]}."
        )
        user = json.dumps(records, ensure_ascii=False)
        response = self._post(
            "/api/chat",
            {
                "model": self.settings.chat_model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "format": "json",
                "stream": False,
                "keep_alive": self.settings.keep_alive,
                "options": {"temperature": 0.1},
            },
        )
        try:
            parsed = json.loads(response["message"]["content"])
            explanation_by_id = {
                int(item["id"]): str(item["explanation"]).strip()
                for item in parsed.get("items", [])
            }
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OllamaError(f"The explanation model returned invalid JSON: {exc}") from exc
        output = []
        for record in records:
            explanation = explanation_by_id.get(int(record["id"]))
            if not explanation:
                explanation = (
                    "The local model did not provide an explanation for this Registry value. "
                    "Its operational meaning requires authoritative Windows documentation."
                )
            output.append(explanation)
        return output

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of metadata and explanations for cosine similarity search."""
        if not texts:
            return []
        response = self._post(
            "/api/embed",
            {
                "model": self.settings.embedding_model,
                "input": texts,
                "truncate": True,
                "keep_alive": self.settings.keep_alive,
            },
        )
        vectors = response.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise OllamaError("Ollama returned an unexpected number of embedding vectors")
        dimension = len(vectors[0]) if vectors else 0
        if not dimension or any(len(vector) != dimension for vector in vectors):
            raise OllamaError("Ollama returned embeddings with inconsistent dimensions")
        normalized = [[float(value) for value in vector] for vector in vectors]
        for vector in normalized:
            if not all(math.isfinite(value) for value in vector) or not any(vector):
                raise OllamaError("Ollama returned a non-finite or zero-length embedding")
        return normalized

    def chat_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Run one tool-aware planner turn using Ollama's native function-call format."""
        return self._post(
            "/api/chat",
            {
                "model": self.settings.chat_model,
                "messages": messages,
                "tools": tools,
                "stream": False,
                "keep_alive": self.settings.keep_alive,
                "options": {"temperature": 0.0},
            },
        )

    def chat_json(self, messages: list[dict[str, Any]], schema: dict[str, Any]) -> str:
        """Request schema-constrained JSON for deterministic Registry change planning."""
        response = self._post(
            "/api/chat",
            {
                "model": self.settings.chat_model,
                "messages": messages,
                "format": schema,
                "stream": False,
                "keep_alive": self.settings.keep_alive,
                "options": {"temperature": 0.0},
            },
        )
        try:
            return str(response["message"]["content"])
        except (KeyError, TypeError) as exc:
            raise OllamaError("Ollama returned no planner message") from exc

    def describe_image(self, image_path: Path, task: str) -> str:
        """Ask the configured local vision model to describe a captured image."""
        raw = image_path.read_bytes()
        encoded = base64.b64encode(raw).decode("ascii")
        response = self._post(
            "/api/chat",
            {
                "model": self.settings.vision_model,
                "messages": [
                    {
                        "role": "user",
                        "content": task,
                        "images": [encoded],
                    }
                ],
                "stream": False,
                "keep_alive": self.settings.keep_alive,
            },
        )
        return str(response.get("message", {}).get("content", "")).strip()
