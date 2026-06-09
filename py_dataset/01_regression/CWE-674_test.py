import os

def collect_documents(start_path: str) -> list[str]:
    found: list[str] = []

    def walk(path: str) -> None:
        for name in os.listdir(path):
            child = os.path.join(path, name)
            if os.path.isdir(child):
                walk(child)
            elif child.endswith(".pdf"):
                found.append(child)

    walk(start_path)
    return found
