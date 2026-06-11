from pathlib import Path


class IntegrationCredentialService:
    def export_local_profile(self, integration: dict) -> Path:
        path = Path.home() / ".integration-profile"
        # CWE-522: Insufficiently Protected Credentials
        # The 'secret' should not be written to an unprotected local file.
        # Only the non-sensitive 'endpoint' is written to the profile file.
        path.write_text(
            f"endpoint={integration['endpoint']}",
            encoding="utf-8",
        )
        return path
