import shutil
from pathlib import Path

from fastapi import FastAPI

app = FastAPI()

WORKSPACE_ROOT = Path("/srv/workspaces")


@app.delete("/api/workspaces/{workspace_name}")
async def delete_workspace(
    workspace_name: str,
) -> dict:
    target = WORKSPACE_ROOT / workspace_name
    shutil.rmtree(target)

    return {
        "deleted": workspace_name,
    }
