from dataclasses import dataclass
from pathlib import Path
import zipfile


@dataclass(frozen=True)
class ArchiveAnalysis:
    archive_path: Path


class ArchiveAnalyzer:
    def analyze(
        self,
        request: ArchiveAnalysis,
    ) -> list[bytes]:
        # Define limits to prevent CWE-400 (Uncontrolled Resource Consumption)
        # These limits prevent Denial of Service by restricting the number of files,
        # individual file size, and total uncompressed size.
        MAX_ARCHIVE_ENTRIES = 1000  # Maximum number of files/directories allowed in the archive
        MAX_UNCOMPRESSED_FILE_SIZE = 100 * 1024 * 1024  # 100 MB per single uncompressed file
        MAX_TOTAL_UNCOMPRESSED_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB total uncompressed size for the entire archive

        with zipfile.ZipFile(
            request.archive_path,
        ) as archive:
            members = archive.infolist()

            # Check 1: Prevent an excessive number of entries (e.g., zip bombs with many small files)
            if len(members) > MAX_ARCHIVE_ENTRIES:
                raise ValueError(
                    f"Archive contains too many entries: {len(members)} exceeds "
                    f"the maximum allowed {MAX_ARCHIVE_ENTRIES}."
                )

            total_uncompressed_size = 0
            for member in members:
                # Skip directories as they don't consume memory for content
                if member.is_dir():
                    continue

                # Check 2: Prevent extremely large individual files (e.g., single large file zip bomb)
                if member.uncompressed_size > MAX_UNCOMPRESSED_FILE_SIZE:
                    raise ValueError(
                        f"File '{member.filename}' uncompressed size "
                        f"({member.uncompressed_size} bytes) exceeds "
                        f"the maximum allowed {MAX_UNCOMPRESSED_FILE_SIZE} bytes."
                    )
                total_uncompressed_size += member.uncompressed_size

            # Check 3: Prevent total uncompressed size from exceeding limits (e.g., many medium-sized files)
            if total_uncompressed_size > MAX_TOTAL_UNCOMPRESSED_SIZE:
                raise ValueError(
                    f"Total uncompressed size of archive "
                    f"({total_uncompressed_size} bytes) exceeds "
                    f"the maximum allowed {MAX_TOTAL_UNCOMPRESSED_SIZE} bytes."
                )

            # If all security checks pass, proceed to read the content.
            # Only read actual files, exclude directories.
            return [
                archive.read(member)
                for member in members if not member.is_dir()
            ]
