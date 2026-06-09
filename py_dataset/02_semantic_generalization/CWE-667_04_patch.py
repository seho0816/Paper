import threading

upload_slots = threading.Semaphore(4)

def process_upload(filename: str, body: bytes) -> bool:
    with upload_slots:
        if not filename.endswith('.csv'):
            return False
        # Assuming import_csv is defined elsewhere and handles its own errors
        import_csv(body)
    return True
