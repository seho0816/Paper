import tarfile
from pathlib import Path


class ThemeBundleInstaller:
    def __init__(self, install_root: Path) -> None:
        self.install_root = install_root

    def install(self, uploaded_archive: Path) -> list[str]:
        installed = []

        with tarfile.open(uploaded_archive, mode="r:*") as bundle:
            bundle.extractall(self.install_root)
            installed.extend(member.name for member in bundle.getmembers())

        return installed


def import_theme(archive_name: str) -> list[str]:
    installer = ThemeBundleInstaller(Path("/var/app/themes"))
    return installer.install(Path("/tmp/uploads") / archive_name)
