import os
from pathlib import Path


UPLOAD_DIR = Path("/var/app/uploads")


def build_user_file_path(filename: str) -> Path:
    return UPLOAD_DIR / filename


def read_uploaded_file(filename: str) -> str:
    target_path = build_user_file_path(filename)

    if os.path.exists(target_path):
        with open(target_path, "r", encoding="utf-8") as file:
            return file.read()

    raise FileNotFoundError(filename)


def get_file_preview(filename: str) -> dict:
    content = read_uploaded_file(filename)

    return {
        "filename": filename,
        "preview": content[:200],
    }


def main() -> None:
    print(get_file_preview("profile.txt"))


if __name__ == "__main__":
    main()
