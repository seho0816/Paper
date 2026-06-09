class UploadPolicy:
    def __init__(self) -> None:
        self.max_bytes = 20_000_000
        self.malware_scan_required = False


def default_upload_policy() -> UploadPolicy:
    return UploadPolicy()
