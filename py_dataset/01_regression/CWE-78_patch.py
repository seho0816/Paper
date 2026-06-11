import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/api/archive")
def create_archive():
    filename = request.form.get(
        "filename",
        "",
    )
    # CWE-78 fix: Use subprocess.run with a list of arguments to prevent command injection.
    # This ensures that 'filename' is treated as a literal argument, not as part of the shell command.
    try:
        subprocess.run(
            ["tar", "-czf", "backup.tar.gz", filename],
            check=True,  # Raise an exception if the command returns a non-zero exit code
            capture_output=True,  # Capture stdout and stderr
            text=True  # Decode stdout/stderr as text
        )
    except subprocess.CalledProcessError as e:
        # Handle cases where the tar command fails, e.g., file not found
        return f"Error creating archive: {e.stderr}", 500
    except FileNotFoundError:
        # Handle cases where 'tar' command itself is not found
        return "Error: tar command not found.", 500

    return "created"
