import subprocess


def install_plugin_package(
    package_url: str,
) -> None:
    subprocess.run(
        [
            "pip",
            "install",
            package_url,
        ],
        check=True,
    )
