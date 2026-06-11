from pathlib import Path

# The base directory where logs are allowed to be exported.
# This path is relative to the current working directory where the script is run.
_EXPORT_BASE_DIR = Path("exported_logs")
# Ensure the base directory exists upon module load.
_EXPORT_BASE_DIR.mkdir(parents=True, exist_ok=True)
# Resolve to an absolute path for robust comparison, handling symlinks and '..' components.
_RESOLVED_EXPORT_BASE_DIR = _EXPORT_BASE_DIR.resolve()


def export_logs(
    destination: str,
    lines: list[str],
) -> str:
    # Construct the full path by joining the base directory with the user-provided destination.
    # This approach effectively sandboxes the output within `_EXPORT_BASE_DIR`.
    target_path = _EXPORT_BASE_DIR / destination

    # Resolve the path to get its absolute, canonical form.
    # This step is crucial for robustly detecting path traversal attempts (e.g., '..').
    resolved_target_path = target_path.resolve()

    # CWE-73 Mitigation: Check if the resolved path is indeed a subpath of the designated export directory.
    # If not, it means the 'destination' tried to escape the allowed directory, indicating a path traversal attack.
    if not resolved_target_path.is_relative_to(_RESOLVED_EXPORT_BASE_DIR):
        # Raise an exception to prevent writing to unauthorized locations.
        raise ValueError("Attempted to write log outside the designated export directory.")
    
    # Ensure all intermediate directories for the target log file exist.
    # For example, if destination is "subdir/log.txt", this creates "exported_logs/subdir".
    resolved_target_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the log content to the safely validated and created path.
    resolved_target_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    return str(resolved_target_path)
