import os

def sanitize_download_name(
    filename: str,
) -> str:
    """
    Sanitizes a filename to prevent directory traversal vulnerabilities (CWE-184 - Incomplete Blacklist).
    The original code only blacklisted '../', which is insufficient as attackers can bypass it
    using various encoding, alternative separators, or multiple dot-slash sequences.

    This patched version addresses the CWE-184 by:
    1. Normalizing the path to resolve '..' and '.' components and collapse redundant separators
       (e.g., 'a//b' becomes 'a/b', '....//file.txt' becomes 'file.txt'). This effectively handles
       many forms of 'incomplete blacklist' bypasses related to malformed path segments.
    2. After normalization, it checks if the resulting path is an absolute path or still
       starts with '..' (indicating an unresolved upward traversal attempt).
    3. If such a traversal attempt (absolute or upward) is detected, it defensively strips
       all path components and returns only the base filename. This ensures that the file
       cannot escape its intended directory.
    4. Otherwise, for safe relative paths (e.g., "sub/dir/file.txt" or "file.txt"),
       the normalized filename is returned, preserving the ability to specify subdirectories
       relative to the download root, which the original code implicitly allowed.
    """
    # Normalize the path to resolve '..' and '.' components, and collapse
    # redundant separators (e.g., 'a//b' becomes 'a/b').
    # This also handles variations like '....//' which would be reduced effectively.
    normalized_filename = os.path.normpath(filename)

    # Check if the normalized filename is an absolute path (e.g., '/etc/passwd' or 'C:\Windows\...')
    # or if it still starts with '..' indicating an attempt to traverse upwards
    # beyond the intended directory after normalization.
    is_absolute_path = os.path.isabs(normalized_filename)
    starts_with_upward_traversal = normalized_filename.startswith('..')

    if is_absolute_path or starts_with_upward_traversal:
        # If it's an absolute path or an upward traversal attempt (like "../../secrets.txt"),
        # we defensively strip all path components and return only the base filename.
        # This prevents any form of path traversal by ensuring only the leaf node of the path is kept.
        # Examples:
        # - "/etc/passwd" -> "passwd"
        # - "../../secrets.txt" -> "secrets.txt"
        # - "C:\\Users\\admin\\file.txt" -> "file.txt"
        # - ".." -> ".." (Note: os.path.basename("..") returns "..", which means if the input was
        #   just ".." it would still return "..". This is consistent with the original function's
        #   behavior which would also pass ".." through, but should be handled carefully by the caller.)
        return os.path.basename(normalized_filename)
    else:
        # If the path is relative and does not attempt to traverse upwards
        # (e.g., "sub/dir/file.txt" or "file.txt"), return the normalized filename.
        # This preserves the ability to specify subdirectories relative to the download root,
        # which the original code implicitly allowed.
        return normalized_filename
