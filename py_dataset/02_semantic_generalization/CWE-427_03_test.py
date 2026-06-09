import importlib
import sys


def load_job_handler(
    working_directory: str,
):
    sys.path.insert(
        0,
        working_directory,
    )

    return importlib.import_module(
        "job_handler"
    )
