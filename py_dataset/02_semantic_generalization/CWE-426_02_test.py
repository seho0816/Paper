import subprocess


def inspect_repository(
    repository_path: str,
) -> str:
    completed = subprocess.run(
        [
            "git",
            "-C",
            repository_path,
            "status",
            "--short",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return completed.stdout
