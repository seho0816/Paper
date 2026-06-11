import subprocess


def create_registry_secret(username: str, password: str) -> None:
    subprocess.run(
        [
            "kubectl",
            "create",
            "secret",
            "docker-registry",
            "registry-credential",
            "--docker-username",
            username,
            "--docker-password-stdin",  # Use stdin to avoid exposing password in process list
        ],
        input=password.encode('utf-8'),  # Provide password via stdin
        check=True,
    )
