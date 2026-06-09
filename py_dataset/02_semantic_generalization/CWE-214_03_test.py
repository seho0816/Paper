import subprocess


def test_smtp(host: str, username: str, password: str) -> None:
    subprocess.run(
        [
            "smtp-check",
            "--host",
            host,
            "--username",
            username,
            "--password",
            password,
        ],
        check=True,
    )
