from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExportLocation:
    tenant_id: str
    category: str


class ExportDirectoryRepository:
    def __init__(
        self,
        shared_root: Path,
    ) -> None:
        self._shared_root = shared_root

    def initialize(
        self,
        location: ExportLocation,
    ) -> Path:
        directory = (
            self._shared_root
            / location.tenant_id
            / location.category
        )
        # CWE-277: Insecure Inherited Permissions
        # Ensure that the created directory has restrictive permissions (e.g., owner only)
        # to prevent unauthorized access, rather than inheriting potentially insecure permissions.
        directory.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700, # Set permissions to rwx for owner only
        )
        return directory
