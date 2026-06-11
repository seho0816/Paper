from pathlib import Path
import os


CACHE_ROOT = Path(
    "/tmp/object-cache"
)


def cache_object(
    object_key: str,
    content: bytes,
) -> Path:
    # Ensure the CACHE_ROOT directory exists to allow for resolution.
    # This also resolves CACHE_ROOT to its canonical absolute path for robust comparison.
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    resolved_cache_root = CACHE_ROOT.resolve()

    # Construct the full path using CACHE_ROOT and the user-provided object_key.
    # pathlib handles the intelligent concatenation of path components.
    potential_path = CACHE_ROOT / object_key

    # Resolve the potential_path to its canonical, absolute form.
    # This processes any '..' components and symbolic links.
    # strict=False allows for paths where the final file or directory might not yet exist,
    # which is necessary because the code will create parent directories later.
    resolved_potential_path = potential_path.resolve(strict=False)

    # Validate that the resolved_potential_path is indeed a sub-path of the resolved_cache_root.
    # This is the core path traversal prevention mechanism.
    try:
        # Python 3.9+ offers Path.is_relative_to() for clear and concise validation.
        if not resolved_potential_path.is_relative_to(resolved_cache_root):
            raise ValueError("Path traversal attempt detected: Resulting path is outside of cache root.")
    except AttributeError:
        # Fallback for Python versions older than 3.9.
        # We check if the string representation of the resolved path starts with the string
        # representation of the resolved cache root, ensuring it's not a sibling path that
        # just happens to share a prefix (e.g., /tmp/cache vs /tmp/cache_bad).
        # We also handle the case where the potential path IS the cache root itself.
        if not (str(resolved_potential_path) == str(resolved_cache_root) or
                str(resolved_potential_path).startswith(str(resolved_cache_root) + os.sep)):
            raise ValueError("Path traversal attempt detected: Resulting path is outside of cache root.")

    # If the path is validated as safe, use the original 'potential_path' for creation and writing.
    # The validation ensures that even if 'potential_path' contains '..' components that resolve
    # to a different canonical path (e.g., CACHE_ROOT/a/../b becomes CACHE_ROOT/b), it remains
    # within the allowed CACHE_ROOT boundary.
    path = potential_path

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_bytes(
        content
    )

    return path
