import os
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class ExportRequest:
    destination: Path
    content: bytes

class ExportService:
    def create(self, request: ExportRequest) -> Path:
        request.destination.write_bytes(request.content)
        os.chmod(request.destination, 0o644)
        return request.destination
