import importlib
import os
import sys


def load_extension():
    extension_path = os.environ[
        "EXTENSION_PATH"
    ]
    sys.path.insert(
        0,
        extension_path,
    )

    return importlib.import_module(
        "application_extension"
    )
