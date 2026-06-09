import subprocess


def encrypt_backup(backup_path: str, encryption_key: str) -> None:
    subprocess.run(
        ["backup-encrypt", "--key", encryption_key, backup_path],
        check=True,
    )
