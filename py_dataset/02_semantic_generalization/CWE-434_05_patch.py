from pathlib import Path


def install_plugin(
    plugin_name: str,
    uploaded_source: bytes,
) -> Path:
    # 1. Sanitize plugin_name to prevent path traversal
    # Path(plugin_name).name extracts the base filename, stripping any directory components.
    # This prevents an attacker from supplying '..%2F..%2Fetc%2Fpasswd' or an absolute path.
    safe_plugin_name = Path(plugin_name).name

    # 2. Validate the file extension to prevent Unrestricted Upload of File with Dangerous Type (CWE-434)
    # Define a whitelist of allowed extensions. For a "plugin", common safe types might be
    # archives (.zip) or application-specific data files.
    # We choose a very restrictive whitelist to prioritize security given the lack of context.
    allowed_extensions = {".zip", ".plugin"} # Example: allow ZIP archives or custom plugin files

    # Get the file extension from the sanitized plugin name and convert to lowercase for case-insensitivity.
    file_extension = Path(safe_plugin_name).suffix.lower()

    if file_extension not in allowed_extensions:
        # If the extension is not in the whitelist, prevent the file from being written.
        # Raising an exception is the most secure and Pythonic way to signal that the
        # operation cannot proceed due to invalid, potentially malicious input.
        # This prevents the creation of files with dangerous types, directly addressing CWE-434.
        raise ValueError(f"Unsupported plugin file type: '{file_extension}'. Allowed types are: {', '.join(allowed_extensions)}")

    # Construct the destination path using the sanitized and validated name.
    # The base directory `/srv/application/plugins` is assumed to exist and be correctly permissioned.
    destination = (
        Path("/srv/application/plugins")
        / safe_plugin_name
    )

    # Write the uploaded source bytes to the secure destination.
    destination.write_bytes(
        uploaded_source,
    )

    return destination
