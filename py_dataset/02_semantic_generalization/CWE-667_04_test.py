import threading

upload_slots = threading.Semaphore(4)

def process_upload(filename: str, body: bytes) -> bool:
    upload_slots.acquire()
    if not filename.endswith('.csv'):
        return False
    import_csv(body)
    upload_slots.release()
    return True
