import subprocess


def deploy_integration(client_id: str, client_secret: str) -> None:
    subprocess.run(
        [
            "integration-deploy",
            "--client-id",
            client_id,
            "--client-secret",
            client_secret,
        ],
        check=True,
    )
