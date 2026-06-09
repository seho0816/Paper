import os
import subprocess


def run_report_plugin(plugin_path: str, report_path: str) -> None:
    subprocess.run(
        [plugin_path, report_path],
        env=os.environ.copy(),
        check=True,
    )
