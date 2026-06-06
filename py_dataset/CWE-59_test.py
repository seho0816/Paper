import sys
from pathlib import Path


class NoteRepository:
    def overwrite_note(self, target_path: Path, content: str) -> None:
        if target_path.exists():
            with target_path.open("w", encoding="utf-8") as file:
                file.write(content)

    def save_user_note(self, raw_path: str, content: str) -> None:
        target = Path(raw_path)
        self.overwrite_note(target, content)


def read_request() -> tuple[str, str]:
    if len(sys.argv) >= 3:
        return sys.argv[1], sys.argv[2]

    return "/tmp/user-note.txt", "updated memo"


def main() -> None:
    path, content = read_request()
    repository = NoteRepository()
    repository.save_user_note(path, content)


if __name__ == "__main__":
    main()
