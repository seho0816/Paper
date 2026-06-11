import subprocess


def call_partner_cli(api_token: str, payload_path: str) -> str:
    result = subprocess.run(
        ["partner-cli", "--token-stdin", "--payload", payload_path],
        input=api_token,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout

