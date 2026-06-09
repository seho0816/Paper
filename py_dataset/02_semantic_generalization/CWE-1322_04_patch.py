import os
import stat
import subprocess

async def inspect_media(file_path: str) -> bytes:
    try:
        # Resolve symbolic links and relative paths to get the canonical path.
        # This helps prevent path traversal and ensures we are checking the actual file.
        resolved_path = os.path.realpath(file_path)

        # Ensure the resolved path points to an existing file.
        if not os.path.exists(resolved_path):
            raise ValueError(f"File does not exist: {file_path}")

        # Get file status to check its type and size.
        file_stat = os.stat(resolved_path)

        # CWE-1322 mitigation: Ensure the file is a regular file.
        # This prevents processing special files (e.g., /dev/random, /dev/zero, named pipes,
        # block/character devices) which can lead to excessive or infinite data reads,
        # consuming system resources and potentially causing a denial of service.
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"Invalid file type: {file_path}. Must be a regular file.")

        # CWE-1322 mitigation: Limit the maximum allowed file size.
        # Processing extremely large files, even regular ones, can lead to excessive
        # resource consumption (CPU, memory, I/O) for the 'ffprobe' process as it reads
        # and parses file headers/metadata.
        # A 5GB limit is chosen as a reasonable upper bound for typical media files
        # to prevent denial-of-service through resource exhaustion.
        MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024 * 1024 # 5 GB
        if file_stat.st_size > MAX_FILE_SIZE_BYTES:
            raise ValueError(f"File size exceeds limit ({MAX_FILE_SIZE_BYTES} bytes): {file_path}")

    except OSError as e:
        # Catch file system related errors (e.g., permissions, non-existent components in path)
        # during path resolution or stat calls.
        raise ValueError(f"File system error during path validation for '{file_path}': {e}") from e
    except ValueError:
        # Re-raise ValueErrors that were already raised for specific validation failures.
        raise

    completed = subprocess.run(
        [
            '/usr/bin/ffprobe',
            '-v',
            'error',
            resolved_path, # Use the validated and resolved path for ffprobe
        ],
        capture_output=True,
        check=True,
        timeout=15,
    )
    return completed.stdout
