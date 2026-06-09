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
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    shutil.copy2(
        source,
        destination,
    )
    return destination
