from pathlib import Path


MEDIA_ROOT = Path(
    "/srv/media"
)


def media_path(
    submitted_name: str,
) -> Path:
    # 1. Construct the potential full path by joining MEDIA_ROOT with the submitted_name.
    #    The pathlib `/` operator handles path segments, including cases where submitted_name
    #    might contain '..' or be an absolute path.
    potential_path = MEDIA_ROOT / submitted_name

    try:
        # 2. Resolve both the base directory and the potential path to their canonical, absolute forms.
        #    `resolve(strict=False)` normalizes paths (e.g., removes '..' components, resolves symlinks)
        #    and makes them absolute, without requiring all components to exist on the filesystem.
        #    This is crucial for preventing path traversal as it provides a standardized path for comparison.
        resolved_media_root = MEDIA_ROOT.resolve(strict=False)
        resolved_potential_path = potential_path.resolve(strict=False)
    except Exception:
        # 3. If any unexpected error occurs during path resolution (e.g., unresolvable symlinks
        #    or malformed path components beyond simple traversal attempts),
        #    return a safe default path to prevent exposing errors or unintended behavior.
        return MEDIA_ROOT

    # 4. Check if the resolved potential path is a subpath (or the same path) of the resolved media root.
    #    This is the core security check to prevent path traversal (CWE-184).
    #    `is_relative_to()` (available from Python 3.9+) efficiently determines if one path is a child
    #    of another after both have been canonicalized.
    if resolved_potential_path.is_relative_to(resolved_media_root):
        # 5. If the path is safe (i.e., it doesn't escape MEDIA_ROOT), reconstruct the path.
        #    We do this by taking the `resolved_media_root` and appending the part of
        #    `resolved_potential_path` that is relative to `resolved_media_root`.
        #    This ensures the returned Path is canonicalized and firmly within `MEDIA_ROOT`,
        #    handling internal '..' components gracefully (e.g., "foo/../bar.txt" becomes "bar.txt"
        #    relative to "foo").
        return resolved_media_root / resolved_potential_path.relative_to(resolved_media_root)
    else:
        # 6. If the resolved path attempts to escape MEDIA_ROOT, it indicates a path traversal attempt.
        #    To address the CWE-184 vulnerability, return a safe, non-traversing path.
        #    Returning `MEDIA_ROOT` itself is a robust and secure fallback, ensuring the function
        #    always returns a valid `Path` object within the controlled directory, maintaining the signature.
        return MEDIA_ROOT
