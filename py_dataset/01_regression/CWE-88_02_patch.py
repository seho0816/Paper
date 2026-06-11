import subprocess


def search_log(
    pattern: str,
    log_path: str,
) -> str:
    result = subprocess.run(
        [
            "grep",
            "-e",  # Explicitly specifies the pattern to prevent argument injection
            pattern,
            log_path,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    return result.stdout
