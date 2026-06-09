import os
import subprocess


ALLOWED_CHILD_ENV = ('LANG', 'LC_ALL', 'TZ')


def run_converter(source_path: str) -> None:
    environment = {
        key: os.environ[key]
        for key in ALLOWED_CHILD_ENV
        if key in os.environ
    }
    environment['PATH'] = '/usr/bin:/bin'
    subprocess.run(['/opt/tools/converter', source_path], env=environment, check=True)
