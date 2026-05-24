import os

def index_directory(path, depth=1):
    print(f"[Depth {depth}] Indexing: {path}")

    try:
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isdir(full_path):
                index_directory(full_path, depth + 1)
            else:
                print(f"  Found file: {item}")

    except PermissionError:
        print(f"  Permission denied: {path}")

index_directory("/Users/Shared/App/Home")