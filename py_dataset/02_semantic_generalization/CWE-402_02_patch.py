import os
import subprocess


def launch_extension(extension_path: str, job_id: str) -> None:
    environment = os.environ.copy()
    # CWE-402: Transmission of Private Information by OS Command or Other Unprivileged Program.
    # If 'job_id' contains sensitive information and 'extension_path' points to an untrusted
    # or unprivileged program, passing 'job_id' via an environment variable could expose it.
    # To fix this, the sensitive 'job_id' is no longer transmitted to the child process.
    # The line 'environment['JOB_ID'] = job_id' has been removed.
    subprocess.Popen([extension_path], env=environment, close_fds=True)
