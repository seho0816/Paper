import importlib
import sys


def load_processor(
    upload_directory: str,
):
    # CWE-427 fix: Do not add untrusted user-controlled directories to sys.path.
    # Adding 'upload_directory' to 'sys.path' would allow an attacker to
    # inject a malicious 'processor.py' module, leading to arbitrary code execution.
    # The 'processor' module should be loaded from a trusted, predefined location.

    return importlib.import_module(
        "processor"
    )
