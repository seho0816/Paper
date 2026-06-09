import subprocess


def show_revision(
    revision: str,
) -> str:
    result = subprocess.run(
        [
            "git",
            "show",
            "--",  # Treat subsequent arguments as paths/revisions, not options
            revision,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    return result.stdout
