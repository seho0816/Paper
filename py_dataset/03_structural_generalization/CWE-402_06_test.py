import os
import subprocess


def plugin_process(function):
    def wrapped(plugin_path: str, *arguments: str):
        command = function(plugin_path, *arguments)
        return subprocess.run(command, env=dict(os.environ), check=True)
    return wrapped


@plugin_process
def execute_export_plugin(plugin_path: str, export_id: str) -> list[str]:
    return [plugin_path, '--export-id', export_id]
