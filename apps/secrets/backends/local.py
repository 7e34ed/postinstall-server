"""Local backend: секреты в памяти (внутри единого блоба)."""
from __future__ import annotations

from ..runtime import SecretsSealed, runtime
from .base import SecretBackend, SecretNotFound


class LocalBackend(SecretBackend):
    name = "local"

    def get(self, path: str, key: str) -> str:
        return runtime.get(path, key)

    def set(self, path: str, key: str, value: str) -> None:
        runtime.set(path, key, value)
        runtime.persist()

    def delete(self, path: str) -> None:
        runtime.delete(path)
        runtime.persist()

    def exists(self, path: str) -> bool:
        return runtime.exists(path)

    def health(self) -> dict:
        try:
            runtime._require()
        except SecretsSealed:
            return {"status": "sealed"}
        return {"status": "ok"}

    def iter_secrets(self, prefix: str = ""):
        from ..runtime import SecretsSealed, runtime
        
        try:
            data = runtime._require()
        except SecretsSealed:
            return

        def walk(node, path_parts: list[str]):
            for k, v in node.items():
                if not isinstance(v, dict):
                    continue
                full = "/".join(path_parts + [k])
                if all(not isinstance(x, dict) for x in v.values()):
                    # лист
                    if prefix and not full.startswith(prefix):
                        continue
                    for key, value in v.items():
                        yield full, key, str(value)
                else:
                    yield from walk(v, path_parts + [k])

        yield from walk(data.get("secrets", {}), [])