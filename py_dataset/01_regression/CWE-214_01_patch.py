import subprocess


def run_migration(database_url: str, password: str) -> None:
    # Remove the password from the command-line arguments to prevent exposure via process listings (e.g., 'ps aux').
    # It is a common secure practice for CLI tools to accept sensitive input like passwords via standard input (stdin)
    # when a dedicated command-line flag is omitted.
    subprocess.run(
        ["db-migrate", "--url", database_url],
        input=password.encode('utf-8'),  # Pass the password securely via stdin
        check=True,
    )
