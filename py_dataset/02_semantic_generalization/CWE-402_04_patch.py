import os
import subprocess


def run_validation_suite(test_file: str) -> int:
    completed = subprocess.run(
        ['/opt/validators/suite', test_file],
        env={},
        check=False,
    )
    return completed.returncode
