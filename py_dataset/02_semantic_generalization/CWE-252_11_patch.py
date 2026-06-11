import subprocess
from pathlib import Path


def restore_backup(backup_path: str) -> None:
    restore_dir = Path("/var/app/restore")
    restore_dir.mkdir(parents=True, exist_ok=True)
    print(f"restore backup from {backup_path} to {restore_dir}")


def verify_backup_signature(backup_path: str, signature_path: str) -> None:
    subprocess.run([
        "gpg",
        "--verify",
        signature_path,
        backup_path,
    ], check=True)


def import_signed_backup(backup_path: str, signature_path: str) -> None:
    verify_backup_signature(backup_path, signature_path)
    restore_backup(backup_path)


def main() -> None:
    import_signed_backup("/tmp/customer.dump", "/tmp/customer.dump.sig")


if __name__ == "__main__":
    main()
