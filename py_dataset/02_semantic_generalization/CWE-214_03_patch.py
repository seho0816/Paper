import subprocess
import os


def test_smtp(host: str, username: str, password: str) -> None:
    # CWE-214: Improper Control of GUI or Access to Restricted Resources.
    # Passing sensitive information like a password directly as a command-line
    # argument can expose it to other users on the system via process listings (e.g., 'ps')
    # and command history. This is an improper control mechanism for accessing
    # a restricted resource (the password).
    # To mitigate this, the password is removed from the command-line arguments
    # and instead passed via an environment variable, which is a more secure practice
    # for sensitive data when interacting with subprocesses.
    # This assumes the 'smtp-check' tool is configured to read the password from
    # an environment variable named 'SMTP_PASSWORD' (or similar).

    # Create a copy of the current environment variables and add the password.
    # This ensures other necessary environment variables are preserved.
    env = os.environ.copy()
    env["SMTP_PASSWORD"] = password

    subprocess.run(
        [
            "smtp-check",
            "--host",
            host,
            "--username",
            username,
            # Removed "--password", password from command-line arguments to prevent exposure
        ],
        env=env,  # Pass the modified environment dictionary with the password
        check=True,
    )
