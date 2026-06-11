import shutil
from pathlib import Path

from fastapi import FastAPI, HTTPException

app = FastAPI()

WORKSPACE_ROOT = Path("/srv/workspaces")


@app.delete("/api/workspaces/{workspace_name}")
async def delete_workspace(
    workspace_name: str,
) -> dict:
    # Construct the potential target path by joining WORKSPACE_ROOT with the provided name.
    potential_target = WORKSPACE_ROOT / workspace_name

    # Resolve the path to its absolute, canonical form.
    # This process handles '..' and '.' segments, and resolves symlinks.
    # strict=True ensures that the path must exist to be resolved,
    # otherwise, a FileNotFoundError is raised.
    try:
        resolved_target = potential_target.resolve(strict=True)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    except Exception as e:
        # Catch any other unexpected errors during path resolution.
        raise HTTPException(status_code=500, detail=f"Failed to resolve workspace path: {e}")

    # Security check for CWE-22 Path Traversal:
    # 1. Ensure the resolved path is strictly a sub-path of WORKSPACE_ROOT.
    #    'is_relative_to()' checks if 'resolved_target' is anywhere beneath 'WORKSPACE_ROOT'.
    # 2. Prevent deletion of WORKSPACE_ROOT itself (e.g., if workspace_name was '.' or empty).
    if not resolved_target.is_relative_to(WORKSPACE_ROOT) or resolved_target == WORKSPACE_ROOT:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Attempted path traversal or deletion of the root workspace directory."
        )

    # Further check to ensure the target is indeed a directory before attempting rmtree.
    if not resolved_target.is_dir():
        raise HTTPException(
            status_code=400,
            detail="Target is not a directory or invalid type for deletion."
        )

    # All security checks passed, proceed with safe deletion.
    shutil.rmtree(resolved_target)

    return {
        "deleted": workspace_name,
    }
