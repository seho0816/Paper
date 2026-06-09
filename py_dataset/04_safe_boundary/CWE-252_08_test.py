import subprocess


def import_signed_backup(
    backup_path: str,
    signature_path: str,
) -> None:
    completed = subprocess.run(
        [
            "gpg",
            "--verify",
            signature_path,
            backup_path,
        ],
        check=False,
    )

    if completed.returncode != 0:
        raise PermissionError(
            "backup signature invalid"
        )

    restore_backup(
        backup_path
    )
