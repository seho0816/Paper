import os
from urllib.parse import unquote


ALLOWED_PREFIX = "/account/"
# Normalize the allowed prefix once for consistent comparison.
# os.path.normpath("/account/") results in "/account".
NORMALIZED_ALLOWED_PREFIX = os.path.normpath(ALLOWED_PREFIX)


def normalize_redirect(
    raw_target: str,
) -> str:
    # First, decode any URL-encoded characters in the raw_target.
    decoded_target = unquote(raw_target)

    # Next, normalize the path to resolve any '..' or '.' sequences,
    # and handle redundant slashes (e.g., //).
    # This step is crucial to prevent path traversal vulnerabilities
    # where encoded or explicit '..' sequences bypass simple prefix checks.
    normalized_target = os.path.normpath(decoded_target)

    # Validate the normalized path:
    # It must either be exactly the allowed prefix directory
    # OR it must be a subpath directly within the allowed prefix directory
    # (i.e., start with the allowed prefix followed by a slash).
    if (
        normalized_target == NORMALIZED_ALLOWED_PREFIX
        or normalized_target.startswith(NORMALIZED_ALLOWED_PREFIX + '/')
    ):
        # If the path is valid after normalization, return the safe, normalized version.
        return normalized_target
    else:
        # If the path attempts to escape the allowed directory or is otherwise invalid, deny it.
        raise ValueError(
            "redirect denied"
        )
