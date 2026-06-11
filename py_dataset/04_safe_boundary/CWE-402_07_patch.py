import os
import subprocess


def run_report_plugin(plugin_path: str, report_path: str) -> None:
    plugin_environment = {
        'PATH': '/usr/bin:/bin',
        'LANG': os.environ.get('LANG', 'C.UTF-8'),
        'REPORT_MODE': 'readonly',
    }
    subprocess.run(
        [plugin_path, report_path],
        env=plugin_environment,
        close_fds=True,
        check=True,
    )

