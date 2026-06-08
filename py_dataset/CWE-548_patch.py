from pathlib import Path


class AttachmentBrowser:
    def __init__(self, upload_root: Path) -> None:
        self.upload_root = upload_root

    def list_all_names(self) -> list[str]:
        names = []

        # CWE-548 Mitigation: Prevent information exposure by only listing regular files
        # and excluding "hidden" files (dotfiles) or directories that might contain
        # sensitive configuration or internal application data.
        for path in self.upload_root.iterdir():
            if path.is_file() and not path.name.startswith('.'):
                names.append(path.name)

        return names


def get_download_index() -> dict[str, list[str]]:
    browser = AttachmentBrowser(Path("/var/app/uploads"))
    return {
        "files": browser.list_all_names(),
    }
