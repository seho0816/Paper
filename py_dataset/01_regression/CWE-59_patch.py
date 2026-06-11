from pathlib import Path


def write_user_note(
    note_path: str,
    content: str,
) -> None:
    target = Path(
        note_path
    )

    if target.is_symlink():
        return

    if target.exists():
        target.write_text(
            content,
            encoding="utf-8",
        )
