import importlib.util
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import os


@dataclass(frozen=True)
class HandlerPackage:
    content: bytes
    handler_name: str


class HandlerRepository:
    def save(
        self,
        package: HandlerPackage,
    ) -> Path:
        current_content_hash = hashlib.sha256(package.content).hexdigest()

        trusted_hashes_json = os.environ.get("TRUSTED_HANDLER_MODULE_HASHES")
        if not trusted_hashes_json:
            raise RuntimeError(
                "Configuration error: TRUSTED_HANDLER_MODULE_HASHES environment variable is not set."
            )
        
        try:
            trusted_hashes = json.loads(trusted_hashes_json)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Configuration error: TRUSTED_HANDLER_MODULE_HASHES is not valid JSON: {e}"
            )

        expected_hash = trusted_hashes.get(package.handler_name)

        if expected_hash is None:
            raise ValueError(
                f"Untrusted handler: '{package.handler_name}' is not in the trusted list."
            )
        
        if current_content_hash != expected_hash:
            raise ValueError(
                f"Integrity check failed for handler '{package.handler_name}'. "
                "Content hash mismatch."
            )

        path = (
            Path("/tmp")
            / (
                package.handler_name
                + ".py"
            )
        )
        path.write_bytes(
            package.content
        )

        return path


class HandlerLoader:
    def load(
        self,
        path: Path,
        module_name: str,
    ) -> object:
        spec = importlib.util.spec_from_file_location(
            module_name,
            path,
        )
        module = importlib.util.module_from_spec(
            spec
        )
        spec.loader.exec_module(
            module
        )

        return module
