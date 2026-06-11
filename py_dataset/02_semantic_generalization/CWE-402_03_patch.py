import os
import subprocess


def render_thumbnail(input_path: str) -> None:
    # CWE-402 fix: Avoid transmitting all parent process environment variables
    # to the child process, as this can leak sensitive information.
    # Instead, create a new environment dictionary with only explicitly
    # required and non-sensitive variables, plus any specific ones needed.
    # For common utilities, 'PATH', 'HOME', 'USER', 'LANG' are often necessary.
    safe_env_vars = ['PATH', 'HOME', 'USER', 'LANG', 'TERM', 'SHELL']
    environment = {}
    for var in safe_env_vars:
        if var in os.environ:
            environment[var] = os.environ[var]

    # Add the specific environment variable intended for the subprocess
    environment['THUMBNAIL_MODE'] = 'safe'

    subprocess.run(
        ['/usr/bin/image-helper', input_path],
        env=environment,
        check=True,
    )
