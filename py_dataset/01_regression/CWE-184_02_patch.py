import os

def sanitize_export_path(
    path_value: str,
) -> str:
    # CWE-184: Incomplete Blacklist for Special Elements
    # The original code only replaces the literal string "/etc/", which is incomplete
    # as it can be bypassed by case variations (e.g., "/ETC/"), path traversal (e.g., "../etc/"),
    # or different path separators (e.g., "\etc\" on Windows).

    # To fix this, we implement a more robust sanitization strategy:
    # 1. Normalize the path to resolve '..' and '.' components and redundant separators.
    # 2. Split the normalized path into individual components.
    # 3. Filter out any component that matches 'etc' (case-insensitive).
    # 4. Reconstruct the path from the sanitized components.

    # Step 1: Normalize the path to handle relative paths (e.g., '..', '.')
    # and collapse redundant separators (e.g., '//').
    normalized_path = os.path.normpath(path_value)

    # Step 2: Split the path into components.
    # Handle drive letter (e.g., C:) for Windows paths.
    drive, tail = os.path.splitdrive(normalized_path)
    
    components = []
    if drive:
        components.append(drive)

    # Handle leading path separator (e.g., '/' for root on Unix-like systems).
    # If the path starts with a separator, add it as a distinct component.
    if tail.startswith(os.path.sep):
        components.append(os.path.sep)
        tail = tail[len(os.path.sep):] # Remove the leading separator from tail

    # Split the remaining 'tail' into segments, filtering out any empty strings
    # that might result from multiple consecutive separators (e.g., "a//b").
    path_segments = [s for s in tail.split(os.path.sep) if s]

    # Step 3: Filter out any component that is 'etc' (case-insensitive).
    sanitized_segments = []
    for segment in path_segments:
        if segment.lower() != 'etc': # Blacklist 'etc' regardless of case
            sanitized_segments.append(segment)
    
    # Step 4: Reconstruct the path from the sanitized components.
    if components and components[0] == os.path.sep:
        # If the original path was absolute (started with /), ensure the reconstructed path also starts with /.
        # If all segments were removed (e.g., "/etc"), return just "/".
        if not sanitized_segments:
            return os.path.sep
        return os.path.join(os.path.sep, *sanitized_segments)
    elif components and drive:
        # If the original path had a drive letter, reconstruct with it.
        return os.path.join(drive, *sanitized_segments)
    else:
        # For relative paths, simply join the sanitized segments.
        return os.path.join(*sanitized_segments)
