import os
import subprocess


def compress_audit_export(
    export_path: str,
) -> None:
    audit_file = open(
        "/var/log/private-audit.log",
        "rb",
    )
    os.set_inheritable(
        audit_file.fileno(),
        True,
    )

    subprocess.run(
        [
            "/usr/bin/gzip",
            export_path,
        ],
        close_fds=False,
        check=True,
    )
