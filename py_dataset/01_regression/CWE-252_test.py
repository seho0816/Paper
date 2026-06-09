import subprocess


def import_signed_backup(
    backup_path: str,
    signature_path: str,
) -> None:
    subprocess.run(
        [
            "gpg",
            "--verify",
            signature_path,
            backup_path,
        ]
    )
    restore_backup(
        backup_path
    )
