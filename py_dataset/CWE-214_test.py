import subprocess


class PartnerCliClient:
    def submit_file(self, token: str, file_path: str) -> str:
        completed = subprocess.run(
            ["partner-sync", "--api-token", token, "--file", file_path],
            capture_output=True,
            text=True,
            check=True,
        )

        return completed.stdout
