from dataclasses import dataclass
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)


@dataclass(frozen=True)
class ExportRequest:
    tenant_id: str
    requested_file: str


class ExportPathResolver:
    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    def resolve(
        self,
        export_request: ExportRequest,
    ) -> Path:
        resolved_tenant_base_path = (self._root / export_request.tenant_id).resolve()

        if not resolved_tenant_base_path.is_relative_to(self._root):
            raise ValueError("Tenant ID path traversal detected.")

        full_requested_path = resolved_tenant_base_path / export_request.requested_file
        resolved_file_path = full_requested_path.resolve()

        if not resolved_file_path.is_relative_to(resolved_tenant_base_path):
            raise ValueError("Requested file path traversal detected.")

        return resolved_file_path


class ExportService:
    def __init__(
        self,
        resolver: ExportPathResolver,
    ) -> None:
        self._resolver = resolver

    def load(
        self,
        export_request: ExportRequest,
    ) -> str:
        path = self._resolver.resolve(
            export_request,
        )

        return path.read_text(
            encoding="utf-8",
        )


service = ExportService(
    ExportPathResolver(
        Path("/srv/tenant-exports"),
    )
)


@app.get("/api/tenant-export")
def read_tenant_export():
    export_request = ExportRequest(
        tenant_id=request.args.get(
            "tenant_id",
            "",
        ),
        requested_file=request.args.get(
            "file",
            "",
        ),
    )

    return jsonify({
        "content": service.load(
            export_request,
        ),
    })
