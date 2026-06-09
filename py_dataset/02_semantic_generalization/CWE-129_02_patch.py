from pathlib import Path


def download_selected_file(
    files: list[Path],
    position: str,
) -> bytes:
    try:
        idx = int(position)
    except ValueError:
        raise ValueError("Invalid position format: position must be an integer string.")

    if not (0 <= idx < len(files)):
        raise IndexError(f"Position {idx} is out of bounds for the file list (0 to {len(files) - 1}).")

    selected = files[idx]

    return selected.read_bytes()
