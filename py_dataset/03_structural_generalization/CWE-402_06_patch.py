import os
import subprocess


def plugin_process(function):
    def wrapped(plugin_path: str, *arguments: str):
        command = function(plugin_path, *arguments)
        # CWE-402 fix: Do not transmit the entire parent process's environment
        # to a potentially untrusted plugin. By default, provide a clean environment.
        # If the plugin requires specific environment variables (e.g., PATH),
        # they should be explicitly whitelisted and added to the 'env' dictionary
        # (e.g., env={'PATH': os.environ.get('PATH')}).
        # For security, avoid inheriting all environment variables.
        return subprocess.run(command, env={}, check=True)
    return wrapped


@plugin_process
def execute_export_plugin(plugin_path: str, export_id: str) -> list[str]:
    return [plugin_path, '--export-id', export_id]
