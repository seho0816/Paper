from pathlib import Path
from urllib.parse import unquote


DOWNLOAD_ROOT = Path(
    "/var/app/downloads"
)


def resolve_download_name(
    raw_name: str,
) -> Path:
    decoded_once = unquote(
        raw_name
    )

    decoded_twice = unquote(
        decoded_once
    )

    # Construct the full prospective path that the user is requesting.
    prospective_path = DOWNLOAD_ROOT / decoded_twice

    # Resolve both the base download root and the prospective path to their
    # canonical, absolute forms. This process normalizes the paths,
    # effectively collapsing '..' (parent directory) and '.' (current directory)
    # components, and resolving any symbolic links to their actual targets.
    resolved_download_root = DOWNLOAD_ROOT.resolve()
    resolved_prospective_path = prospective_path.resolve()

    # Validate that the resolved prospective path is indeed a subpath of
    # the resolved download root. If it's not, it indicates an attempted
    # directory traversal outside the allowed download directory.
    # Path.is_relative_to() (available from Python 3.9) is the most robust
    # and idiomatic way to perform this check.
    if not resolved_prospective_path.is_relative_to(resolved_download_root):
        raise ValueError(
            "invalid path: attempted directory traversal"
        )

    # If the path is validated as safe and within the download root,
    # return the path object as originally intended. The `decoded_twice`
    # part, even if it contained `../` that resolved safely, has been checked.
    return (
        DOWNLOAD_ROOT
        / decoded_twice
    )
