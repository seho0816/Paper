from pathlib import Path


class SecretExportService:
    def Create(
        self,
        request,
        context,
    ):
        path = Path(
            "/var/tmp"
        ) / "secret-export.json"
        path.write_bytes(
            request.body
        )

        return {
            "path": str(
                path
            ),
        }
