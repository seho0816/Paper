import subprocess


class PluginInstaller:
    def install_from_url(self, wheel_url: str) -> None:
        subprocess.run(
            ["pip", "install", wheel_url],
            check=True,
        )


def install_requested_plugin(download_url: str) -> None:
    installer = PluginInstaller()
    installer.install_from_url(download_url)
