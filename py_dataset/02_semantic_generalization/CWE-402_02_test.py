import os
import subprocess


def launch_extension(extension_path: str, job_id: str) -> None:
    environment = os.environ.copy()
    environment['JOB_ID'] = job_id
    subprocess.Popen([extension_path], env=environment, close_fds=True)
