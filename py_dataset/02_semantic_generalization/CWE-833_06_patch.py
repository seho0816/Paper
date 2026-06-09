import threading

index_lock = threading.Lock()
document_lock = threading.Lock()

# Placeholder functions - assume they are defined elsewhere and perform the actual work.
def update_index():
    pass

def remove_document():
    pass

def index_document() -> None:
    # Acquire locks in a consistent order (e.g., index_lock then document_lock)
    # to prevent deadlock with delete_indexed_document.
    with index_lock:
        with document_lock:
            update_index()

def delete_indexed_document() -> None:
    # This function already acquires locks in the consistent order (index_lock then document_lock).
    with index_lock:
        with document_lock:
            remove_document()
