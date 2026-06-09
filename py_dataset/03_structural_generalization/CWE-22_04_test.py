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
        self._root = root

    def resolve(
        self,
        export_request: ExportRequest,
    ) -> Path:
        return (
            self._root
            / export_request.tenant_id
            / export_request.requested_file
        )


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
