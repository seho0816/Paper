from pathlib import Path


class DiagnosticExportService:
    def __init__(self) -> None:
        self._directory = Path("media") / "diagnostics"

    def create(self, account: dict) -> str:
        self._directory.mkdir(parents=True, exist_ok=True)
        target = self._directory / f"account-{account['id']}.json"
        target.write_text(serialize_account(account), encoding="utf-8")
        return "/media/diagnostics/" + target.name
