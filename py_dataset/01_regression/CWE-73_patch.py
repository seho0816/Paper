from pathlib import Path


def export_report(
    output_path: str,
    rows: list[str],
) -> Path:
    # CWE-73 fix: Prevent directory traversal and arbitrary file writes.
    # 1. Define a base directory to restrict file operations.
    #    Path.cwd() (current working directory) is used as a default safe location
    #    when no other base directory is specified or configured.
    base_dir = Path.cwd().resolve()

    # 2. Convert the user-provided output_path to a Path object.
    requested_path = Path(output_path)

    # 3. Disallow absolute paths directly provided by the user to prevent them from
    #    overriding the intended base_dir. If absolute paths were allowed, an attacker
    #    could simply provide `/etc/passwd` instead of `../../etc/passwd`.
    if requested_path.is_absolute():
        raise ValueError(
            "Absolute paths are not allowed for output_path to prevent arbitrary file writes. "
            "Please provide a relative path."
        )

    # 4. Construct the full path by joining the base directory with the user's relative path.
    #    This ensures that the user's path is always interpreted relative to our controlled base_dir.
    full_path_candidate = base_dir / requested_path
    
    # 5. Resolve the path to get its canonical form. This handles '..' and '.' components
    #    and resolves any symbolic links to their actual targets.
    resolved_path = full_path_candidate.resolve()

    # 6. Crucial check: Ensure the resolved path is still contained within our base directory.
    #    If resolved_path is not relative to base_dir, it means a path traversal attempt
    #    (e.g., using '..') has successfully navigated outside the allowed directory.
    if not resolved_path.is_relative_to(base_dir):
        raise ValueError(
            "Path traversal attempt detected. The output path must be within the current "
            "working directory or its subdirectories."
        )

    # 7. Use the validated and resolved path for file operations.
    target = resolved_path
    
    # Note: The original code does not explicitly create parent directories.
    # Adding 'target.parent.mkdir(parents=True, exist_ok=True)' would be a functional change.
    # Adhering to rule 4 ("기능을 추가하거나 전체를 재작성하지 마세요."),
    # we maintain the original behavior where write_text will raise FileNotFoundError
    # if parent directories do not exist.

    target.write_text(
        "\n".join(rows),
        encoding="utf-8",
    )

    return target
