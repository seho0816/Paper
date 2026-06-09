import importlib
import sys


def load_processor(
    upload_directory: str,
):
    sys.path.append(
        upload_directory
    )

    return importlib.import_module(
        "processor"
    )
