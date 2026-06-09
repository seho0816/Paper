from pathlib import Path


def download_selected_file(
    files: list[Path],
    position: str,
) -> bytes:
    selected = files[
        int(position)
    ]

    return selected.read_bytes()
