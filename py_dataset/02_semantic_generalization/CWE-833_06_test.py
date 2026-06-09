import threading

index_lock = threading.Lock()
document_lock = threading.Lock()

def index_document() -> None:
    with document_lock:
        with index_lock:
            update_index()

def delete_indexed_document() -> None:
    with index_lock:
        with document_lock:
            remove_document()
