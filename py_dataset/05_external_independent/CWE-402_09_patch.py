import os
import subprocess
from celery import shared_task


@shared_task
def analyze_uploaded_file(path: str) -> int:
    result = subprocess.run(
        ['/opt/plugins/analyzer', path],
        env={},
        check=False,
    )
    return result.returncode
