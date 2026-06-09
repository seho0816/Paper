import os


def extract_archive_as_group(archive_path: str, group_id: int) -> None:
    try:
        os.setgid(group_id)
        extract_archive(archive_path)  # Move this call inside the try block
    except OSError:
        log_privilege_warning()
