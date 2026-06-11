import shutil
from pathlib import Path


JOB_SCRIPT_ROOT = Path('/srv/jobs/scripts')


def stage_user_script(
    script_path: str,
    job_id: str,
) -> Path:
    source = Path(script_path)
    destination = (
        JOB_SCRIPT_ROOT
        / job_id
        / source.name
    )
    # CWE-281: Improper Preservation of Permissions
    # When creating new directories, their permissions might be too permissive
    # due to the system's default umask. Explicitly setting a secure mode
    # like 0o700 ensures that only the owner has full access, preventing
    # unauthorized access or modification by others.
    destination.parent.mkdir(
        mode=0o700,  # Set restrictive permissions for the new directory (owner rwx, no access for group/others)
        parents=True,
        exist_ok=True,
    )
    shutil.copy2(
        source,
        destination,
    )
    return destination
