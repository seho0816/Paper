import os

def collect_documents(start_path: str) -> list[str]:
    found: list[str] = []
    # Set to store canonical paths of visited directories to prevent uncontrolled recursion
    visited_dirs: set[str] = set()

    def walk(path: str) -> None:
        # Resolve the path to its canonical form to handle symbolic links and identify actual directories.
        # This is crucial for detecting directory traversal cycles.
        try:
            canonical_path = os.path.realpath(path)
        except OSError:
            # Handle cases where os.path.realpath fails (e.g., path does not exist, broken symlink).
            # The original code would also raise an error (e.g., FileNotFoundError on os.listdir).
            return

        if canonical_path in visited_dirs:
            return # Already visited this directory (via its canonical path), skip to prevent recursion loop

        visited_dirs.add(canonical_path)

        # The original code would raise an error if 'path' is not a directory or inaccessible.
        # We proceed with os.listdir, and any OSError will propagate as in the original design,
        # but the recursion itself is now controlled.
        for name in os.listdir(path):
            child = os.path.join(path, name)
            if os.path.isdir(child):
                walk(child)
            elif child.endswith(".pdf"):
                found.append(child)

    walk(start_path)
    return found
