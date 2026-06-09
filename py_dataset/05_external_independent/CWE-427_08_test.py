import importlib
import sys


def load_zipped_extension(
    archive_path: str,
):
    sys.path.insert(
        0,
        archive_path,
    )

    return importlib.import_module(
        "extension"
    )
