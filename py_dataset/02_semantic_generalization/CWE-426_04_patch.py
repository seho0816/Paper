import os


def start_backup(
    source: str,
    destination: str,
) -> None:
    trusted_rsync_paths = [
        "/usr/bin/rsync",
        "/bin/rsync",
        "/usr/local/bin/rsync",
    ]
    
    rsync_executable = None
    for path in trusted_rsync_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            rsync_executable = path
            break

    if not rsync_executable:
        raise FileNotFoundError("rsync executable not found in trusted locations.")

    os.execv(
        rsync_executable,
        [
            "rsync",
            "-a",
            source,
            destination,
        ],
    )
