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
            "--docker-password",
            password,
        ],
        check=True,
    )
