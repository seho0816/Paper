import hashlib
from fastapi import UploadFile, HTTPException, status

MAX_FILES = 10
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

async def hash_uploaded_files(
    uploaded_files: list[UploadFile],
) -> dict[str, str]:
    # CWE-770: 파일 개수 통제
    if len(uploaded_files) > MAX_FILES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Too many files")

    results = {}

    for uploaded_file in uploaded_files:
        sha256_hash = hashlib.sha256()
        chunk_size = 8192 
        total_size = 0

        while True:
            chunk = await uploaded_file.read(chunk_size)
            if not chunk:
                break
            
            # CWE-770: 개별 파일 크기 누적 통제
            total_size += len(chunk)
            if total_size > MAX_FILE_SIZE:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")
                
            sha256_hash.update(chunk)

        results[uploaded_file.filename or "unnamed"] = sha256_hash.hexdigest()

    return results