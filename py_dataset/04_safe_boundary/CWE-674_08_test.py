import os

MAX_DEPTH = 20

def collect_files(start_path: str) -> list[str]:
    visited: set[str] = set()
    files: list[str] = []

    def walk(path: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            return
        real_path = os.path.realpath(path)
        if real_path in visited:
            return
        visited.add(real_path)
        for name in os.listdir(real_path):
            child = os.path.join(real_path, name)
            if os.path.isdir(child):
                walk(child, depth + 1)
            else:
                files.append(child)

    walk(start_path, 0)
    return files
