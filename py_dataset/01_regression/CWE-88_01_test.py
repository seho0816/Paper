import subprocess


def show_revision(
    revision: str,
) -> str:
    result = subprocess.run(
        [
            "git",
            "show",
            revision,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    return result.stdout
