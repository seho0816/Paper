import os

# CWE-674: Uncontrolled Recursion Fix
# Add a maximum recursion depth to prevent stack overflow or resource exhaustion
MAX_RECURSION_DEPTH = 10 

def index_directory(path, depth=1):
    print(f"[Depth {depth}] Indexing: {path}")

    # Enforce maximum recursion depth
    if depth > MAX_RECURSION_DEPTH:
        print(f"  Max recursion depth ({MAX_RECURSION_DEPTH}) exceeded for: {path}")
        return

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
