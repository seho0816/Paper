import subprocess
import shutil


def inspect_repository(
    repository_path: str,
) -> str:
    git_path = shutil.which("git")
    if not git_path:
        # If 'git' executable is not found in the system's PATH,
        # subprocess.run would raise a FileNotFoundError.
        # Explicitly raising it here ensures clarity and consistent behavior.
        raise FileNotFoundError("Git executable not found in system PATH.")

    completed = subprocess.run(
        [
            git_path,  # Use the absolute path to 'git' to prevent untrusted search path vulnerability (CWE-426)
            "-C",
            repository_path,
            "status",
            "--short",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return completed.stdout
