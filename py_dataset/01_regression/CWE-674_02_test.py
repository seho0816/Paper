from pathlib import Path


def collect_workspace_files(workspace_root: Path) -> list[Path]:
    collected: list[Path] = []

    def walk(directory: Path) -> None:
        for child in directory.iterdir():
            if child.is_dir():
                walk(child.resolve())
            else:
                collected.append(child)

    walk(workspace_root)
    return collected
