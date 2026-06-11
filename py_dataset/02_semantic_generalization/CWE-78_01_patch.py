import subprocess

from fastapi import FastAPI, Query

app = FastAPI()


@app.get("/api/network/ping")
async def ping_host(
    host: str = Query(...),
) -> dict:
    # CWE-78 fix: Pass command as a list of arguments to prevent shell injection.
    # This ensures that user input 'host' is treated as a single argument
    # and not interpreted as shell commands.
    command = ["ping", "-c", "1", host]

    completed = subprocess.run(
        command,
        # CWE-78 fix: Set shell=False (or omit, as False is the default)
        # to prevent the command string from being processed by the shell.
        # This, combined with passing the command as a list, prevents OS command injection.
        shell=False,
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "output": completed.stdout,
    }
