import threading

upload_slots = threading.Semaphore(4)

def process_upload(filename: str, body: bytes) -> bool:
    upload_slots.acquire()
    try:
        if not filename.endswith('.csv'):
            return False
        import_csv(body)
        return True
    finally:
        upload_slots.release()

