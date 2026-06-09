from pathlib import Path


def collect_workspace_files(workspace_root: Path) -> list[Path]:
    collected: list[Path] = []
    visited_directories: set[Path] = set()

    def walk(directory: Path) -> None:
        # Resolve the current directory to its canonical path to handle symlinks
        # and ensure consistent tracking of visited directories.
        resolved_directory = directory.resolve()

        # If this directory (or its canonical form) has already been visited,
        # return immediately to prevent uncontrolled recursion (CWE-674).
        if resolved_directory in visited_directories:
            return

        # Mark the current resolved directory as visited.
        visited_directories.add(resolved_directory)

        for child in directory.iterdir():
            if child.is_dir():
                # Recursively call walk on the resolved child path,
                # consistent with the original code's behavior for recursion.
                walk(child.resolve())
            else:
                collected.append(child)

    # Start the walk from the workspace root. The `walk` function itself
    # will handle resolving this path and adding it to `visited_directories`.
    walk(workspace_root)
    return collected
