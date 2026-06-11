from pathlib import Path
from urllib.parse import unquote


BASE_DIR = Path(
    "/var/app/downloads"
)


def build_download_path(
    raw_name: str,
) -> Path:
    # CWE-180 fix: Perform URL decoding *before* applying security checks.
    # This ensures that encoded directory traversal sequences (e.g., "%2e%2e%2f")
    # are properly evaluated by the validation logic.
    decoded_name = unquote(
        raw_name
    )

    if (
        ".." in decoded_name  # Apply path traversal checks to the decoded name
        or decoded_name.startswith(
            "/"
        )  # Apply absolute path checks to the decoded name
    ):
        raise ValueError(
            "invalid file name"
        )

    # Robust path validation: Ensure the final path, once constructed and resolved,
    # stays strictly within the intended base directory. This prevents traversal
    # even if simple string checks are bypassed (e.g., via symlinks or
    # more complex path components like `foo/./../bar`).
    target_path = BASE_DIR / decoded_name
    try:
        # Resolve the path to its canonical form, handling '..' and symlinks.
        resolved_path = target_path.resolve()
        # Check if the resolved path is a subpath of the base directory's resolved path.
        if not resolved_path.is_relative_to(BASE_DIR.resolve()):
            raise ValueError("invalid file path: traversal detected after resolution")
    except Exception as e:
        # Catch any errors during path resolution (e.g., non-existent components, permission issues)
        # and treat them as security violations.
        raise ValueError(f"invalid file path: resolution failed - {e}") from e

    # The path construction remains the same, now operating on a validated and decoded name.
    return target_path
