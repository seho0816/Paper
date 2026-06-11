import re
import subprocess


REVISION_PATTERN = re.compile(
    r"^[A-Fa-f0-9]{7,40}$"
)


def show_revision(
    revision: str,
) -> str:
    if not REVISION_PATTERN.fullmatch(
        revision
    ):
        raise ValueError(
            "invalid revision"
        )

    result = subprocess.run(
        [
            "git",
            "show",
            "--",
            revision,
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout

