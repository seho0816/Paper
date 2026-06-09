import subprocess

from fastapi import FastAPI, Query

app = FastAPI()


@app.get("/api/network/ping")
async def ping_host(
    host: str = Query(...),
) -> dict:
    command = f"ping -c 1 {host}"

    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "output": completed.stdout,
    }
