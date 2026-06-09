def process_upload(
    upload_slots,
    upload: bytes,
) -> str:
    upload_slots.acquire()
    try:
        result = store_upload(
            upload
        )
        upload_slots.release()
        return result
    finally:
        upload_slots.release()
