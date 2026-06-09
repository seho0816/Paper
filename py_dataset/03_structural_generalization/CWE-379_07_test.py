from pathlib import Path


class ResetExportService:
    def create(
        self,
        content: str,
    ) -> Path:
        path = Path(
            "/tmp/password-resets.csv"
        )
        path.write_text(
            content,
            encoding="utf-8",
        )

        return path
