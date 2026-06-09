import subprocess


def inspect_archive(
    archive_name: str,
) -> str:
    completed = subprocess.run(
        [
            "7z",
            "l",
            archive_name,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    return completed.stdout
