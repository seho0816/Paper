from pathlib import Path


class IntegrationCredentialService:
    def export_local_profile(self, integration: dict) -> Path:
        path = Path.home() / ".integration-profile"
        path.write_text(
            f"endpoint={integration['endpoint']}\nsecret={integration['secret']}",
            encoding="utf-8",
        )
        return path
