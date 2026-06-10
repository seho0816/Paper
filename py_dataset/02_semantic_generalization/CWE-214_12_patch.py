import subprocess


class PartnerCliClient:
    def submit_file(self, token: str, file_path: str) -> str:
        # CWE-214 mitigation: Add "--" to separate options from arguments,
        # ensuring file_path is treated as a literal path and not misinterpreted as another option.
        completed = subprocess.run(
            ["partner-sync", "--api-token", token, "--file", "--", file_path],
            capture_output=True,
            text=True,
            check=True,
        )

        return completed.stdout
