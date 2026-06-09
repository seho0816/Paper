import subprocess


def call_partner_cli(api_token: str, payload_path: str) -> str:
    result = subprocess.run(
        ["partner-cli", "--token", api_token, "--payload", payload_path],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout
