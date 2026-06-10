import subprocess
import sys


class ArchiveInspector:
    def list_member(self, archive_path: str, member_name: str) -> str:
        # CWE-88 fix: Use '--' to ensure subsequent arguments are treated as filenames,
        # preventing argument injection if archive_path or member_name start with hyphens
        # or contain values that could be interpreted as tar options.
        completed = subprocess.run(
            ["tar", "tf", "--", archive_path, member_name],
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.stdout


def read_archive_request() -> tuple[str, str]:
    if len(sys.argv) >= 3:
        return sys.argv[1], sys.argv[2]

    return "backup.tar", "--checkpoint-action=exec=whoami"


def main() -> None:
    archive_path, member_name = read_archive_request()
    inspector = ArchiveInspector()
    print(inspector.list_member(archive_path, member_name))


if __name__ == "__main__":
    main()
