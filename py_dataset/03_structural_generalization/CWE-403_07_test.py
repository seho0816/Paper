import os
import subprocess


class PluginService:
    def execute(
        self,
        plugin_path: str,
    ) -> None:
        credential = open(
            "/var/app/credentials/service.pem",
            "rb",
        )
        os.set_inheritable(
            credential.fileno(),
            True,
        )

        subprocess.Popen(
            [
                plugin_path,
            ],
            close_fds=False,
        )
