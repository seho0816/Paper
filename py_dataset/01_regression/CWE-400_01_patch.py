import zipfile
from pathlib import Path


# Define sensible limits for resource consumption (CWE-400)
# These values should be adjusted based on specific application requirements and available resources.
MAX_TOTAL_UNCOMPRESSED_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB
MAX_INDIVIDUAL_FILE_SIZE = 100 * 1024 * 1024         # 100 MB
MAX_NUMBER_OF_FILES = 10000


def extract_archive(
    archive_path: Path,
    destination: Path,
) -> None:
    with zipfile.ZipFile(
        archive_path,
    ) as archive:
        # Validate total uncompressed size, individual file sizes, and number of files
        # to prevent CWE-400 (Denial of Service) via zip bombs.
        total_uncompressed_size = 0
        num_files = 0

        for file_info in archive.infolist():
            # Check individual file size
            if file_info.file_size > MAX_INDIVIDUAL_FILE_SIZE:
                raise ValueError(
                    f"Archive contains a file '{file_info.filename}' "
                    f"exceeding maximum allowed individual file size of "
                    f"{MAX_INDIVIDUAL_FILE_SIZE / (1024*1024):.0f} MB"
                )

            total_uncompressed_size += file_info.file_size
            num_files += 1

            # Check total uncompressed size
            if total_uncompressed_size > MAX_TOTAL_UNCOMPRESSED_SIZE:
                raise ValueError(
                    f"Archive exceeds maximum allowed total uncompressed size of "
                    f"{MAX_TOTAL_UNCOMPRESSED_SIZE / (1024*1024*1024):.0f} GB"
                )
            # Check number of files
            if num_files > MAX_NUMBER_OF_FILES:
                raise ValueError(
                    f"Archive exceeds maximum allowed number of files ({MAX_NUMBER_OF_FILES})"
                )

        # If all checks pass, extract the archive
        archive.extractall(
            destination,
        )
