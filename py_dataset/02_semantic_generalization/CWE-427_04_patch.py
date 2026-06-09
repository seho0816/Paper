import os
import subprocess


def run_plugin_worker(
    plugin_directory: str,
) -> None:
    environment = dict(
        os.environ
    )
    # CWE-427 (Uncontrolled Search Path Element) vulnerability is caused by setting
    # PYTHONPATH to an uncontrolled `plugin_directory`. This allows an attacker
    # to inject malicious modules that could be loaded instead of legitimate ones.
    # To fix this, the untrusted `plugin_directory` is removed from PYTHONPATH.
    # The `plugin_worker` module will now be searched in the standard Python module
    # search paths (e.g., site-packages, etc.) as determined by the system's Python
    # environment, preventing module hijacking.
    if "PYTHONPATH" in environment:
        del environment["PYTHONPATH"]

    subprocess.run(
        [
            "python",
            "-m",
            "plugin_worker",
        ],
        check=True,
        env=environment,
    )
