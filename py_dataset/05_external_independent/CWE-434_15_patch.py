from pathlib import Path


def resolve_upload_plugin(
    _root,
    _info,
    plugin_filename: str,
    source_code: str,
) -> dict:
    # CWE-434 fix: Prevent unrestricted upload of files with dangerous types.
    # This involves two main aspects:
    # 1. Path traversal: Ensure the file is written only to the intended directory.
    # 2. Dangerous file type: Ensure the file has a safe extension, assuming Python plugins are intended.

    # Step 1: Sanitize the filename to prevent path traversal.
    # Path(plugin_filename).name extracts only the final component of a path,
    # effectively stripping any directory components like '..', '/', '\'.
    sanitized_basename = Path(plugin_filename).name

    # Step 2: Ensure the file has a safe extension.
    # Assuming the intended "plugins" are Python source code, we force the extension to '.py'.
    # This addresses the "dangerous type" aspect of CWE-434 by preventing execution of
    # potentially malicious non-Python scripts (e.g., .sh, .php, .exe).
    # Path(sanitized_basename).stem extracts the filename without its original suffix.
    safe_filename_stem = Path(sanitized_basename).stem
    final_safe_filename = safe_filename_stem + ".py"

    destination = (
        Path("/srv/plugins")
        / final_safe_filename
    )
    destination.write_text(
        source_code,
        encoding="utf-8",
    )

    return {
        "installed": str(destination),
    }
