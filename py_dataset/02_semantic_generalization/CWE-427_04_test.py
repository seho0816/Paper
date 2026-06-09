import os
import subprocess


def run_plugin_worker(
    plugin_directory: str,
) -> None:
    environment = dict(
        os.environ
    )
    environment[
        "PYTHONPATH"
    ] = plugin_directory

    subprocess.run(
        [
            "python",
            "-m",
            "plugin_worker",
        ],
        check=True,
        env=environment,
    )
