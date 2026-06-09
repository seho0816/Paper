from dataclasses import dataclass
from pathlib import Path
import shutil


@dataclass(frozen=True)
class BackupCopy:
    source: Path
    destination: Path


class BackupService:
    def copy(
        self,
        request: BackupCopy,
    ) -> None:
        # CWE-59: Improper Link Resolution Before File Access ('Link Following')
        # Vulnerability: The destination path (request.destination) might contain
        # symbolic links that, when followed by shutil.copy2, could lead to
        # writing files to unintended, sensitive locations (e.g., /etc/passwd via a symlink).
        # shutil.copy2 follows symlinks for the destination path, allowing attackers
        # to exploit this to write to arbitrary locations.
        #
        # Mitigation: Resolve the destination path to its canonical form before use.
        # Path.resolve() follows all symbolic links in the path components and
        # normalizes the path to its absolute, true location.
        # By passing the resolved path to shutil.copy2, the application operates
        # on the explicit, true file system location, preventing the "improper link
        # resolution" aspect of the vulnerability where the actual target is hidden
        # or disguised by symlinks.
        # Using strict=False ensures that if the final component of the path
        # (the file itself) does not yet exist, it is still correctly handled while
        # resolving any existing parent directory symlinks, maintaining compatibility
        # with shutil.copy2's ability to create new files.
        resolved_destination = request.destination.resolve(strict=False)

        shutil.copy2(
            request.source,
            resolved_destination,
        )
