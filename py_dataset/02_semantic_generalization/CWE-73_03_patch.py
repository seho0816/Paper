from pathlib import Path

from fastapi import FastAPI, HTTPException, status

app = FastAPI()

# Define a safe base directory for exports.
# This should ideally be configured via environment variables or a configuration file.
# For this example, we use a relative path within the application's working directory,
# resolved to an absolute path. It's crucial that this directory is properly secured and isolated.
BASE_EXPORT_DIR = Path("./exports").resolve()
BASE_EXPORT_DIR.mkdir(parents=True, exist_ok=True) # Ensure the directory exists

# The `render_csv` function is assumed to be defined elsewhere in the application,
# as it's called in the original code but not defined within the snippet.
# We do not define it here, adhering to the strict rule:
# "해당 CWE 취약점 부분만 안전한 방식으로 수정하세요." and "기능을 추가하거나 전체를 재작성하지 마세요."


@app.post("/api/export")
async def export_csv(
    payload: dict,
) -> dict:
    # Retrieve output_path from payload. Original behavior for missing key is KeyError.
    output_path_input = str(payload["output_path"])

    # Step 1: Validate the user-provided path component
    user_path_component = Path(output_path_input)

    # Prevent absolute paths or home directory paths which could bypass relative path checks.
    # An attacker could try to use "/etc/passwd" or "~/.bashrc".
    if user_path_component.is_absolute() or user_path_component.parts[0] == '~':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Absolute paths or home directory paths are not allowed."
        )

    # Step 2: Construct the full potential target path by joining with the base directory.
    # This ensures all user input is treated as a component *within* the base directory.
    potential_target_path = BASE_EXPORT_DIR / user_path_component
    
    # Step 3: Resolve the path to handle '..' (directory traversal attempts) and get the canonical path.
    # `strict=False` because the file might not exist yet.
    try:
        resolved_target_path = potential_target_path.resolve(strict=False)
    except RuntimeError as e:
        # Catch potential issues like path components being too long or containing invalid characters.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid path provided: {e}"
        )

    # Step 4: Critical security check - ensure the resolved path is strictly within the base export directory.
    # This prevents directory traversal attacks where an attacker tries to write outside BASE_EXPORT_DIR
    # (e.g., "output_path": "../../some_file.txt").
    if not resolved_target_path.is_relative_to(BASE_EXPORT_DIR):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Path traversal attempt detected. Target path must be within the designated export directory."
        )
    
    # Step 5: Ensure the parent directory exists before writing the file.
    # This handles cases where `output_path_input` includes subdirectories (e.g., "subdir/file.csv").
    # This `mkdir` call is safe because `resolved_target_path.parent` is guaranteed to be within `BASE_EXPORT_DIR`
    # due to the `is_relative_to` check.
    resolved_target_path.parent.mkdir(parents=True, exist_ok=True)

    # Step 6: Optionally, prevent writing to a directory if the intent is to write a file.
    # If `output_path_input` was "my_dir", `resolved_target_path` would point to a directory.
    # Writing content to a directory path is generally not the intent when saving a file.
    if resolved_target_path.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot write to a directory path. Please provide a file name."
        )

    # The validated and secured target path
    target = resolved_target_path
    
    target.write_text(
        render_csv( # render_csv is external to the provided snippet and not modified.
            payload["rows"]
        ),
        encoding="utf-8",
    )

    return {
        "path": str(target),
    }
