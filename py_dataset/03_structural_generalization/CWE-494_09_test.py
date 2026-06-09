import importlib.util
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HandlerPackage:
    content: bytes
    handler_name: str


class HandlerRepository:
    def save(
        self,
        package: HandlerPackage,
    ) -> Path:
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
