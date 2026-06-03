from pathlib import Path


class AttachmentBrowser:
    def __init__(self, upload_root: Path) -> None:
        self.upload_root = upload_root

    def list_all_names(self) -> list[str]:
        names = []

        for path in self.upload_root.iterdir():
            names.append(path.name)

        return names


def get_download_index() -> dict[str, list[str]]:
    browser = AttachmentBrowser(Path("/var/app/uploads"))
    return {
        "files": browser.list_all_names(),
    }
