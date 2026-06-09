import os
import subprocess


def run_plugin(
    plugin_path: str,
) -> None:
    database_file = open(
        "/srv/data/customers.db",
        "rb",
    )
    os.set_inheritable(
        database_file.fileno(),
        True,
    )

    subprocess.Popen(
        [
            plugin_path,
        ],
        close_fds=False,
    )
