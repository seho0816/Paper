import subprocess
import os


def deploy_integration(client_id: str, client_secret: str) -> None:
    # Sensitive information (client_secret) should not be passed directly as command-line arguments
    # as it can be exposed through process listings (e.g., `ps aux`) or logs.
    # Instead, pass it securely via environment variables.

    # Build the command arguments, excluding the client_secret.
    command = [
        "integration-deploy",
        "--client-id",
        client_id,
    ]

    # Create a copy of the current process's environment variables.
    # This ensures that the subprocess inherits necessary environment variables (like PATH, HOME, etc.).
    env_with_secret = os.environ.copy()
    
    # Add the client_secret to the environment variables for the subprocess.
    # The 'integration-deploy' tool is expected to read the secret from this environment variable.
    env_with_secret["INTEGRATION_CLIENT_SECRET"] = client_secret

    subprocess.run(
        command,
        env=env_with_secret,  # Pass the modified environment to the subprocess.
        check=True,
    )
