import hashlib

from fastapi import UploadFile


async def hash_uploaded_files(
    uploaded_files: list[UploadFile],
) -> dict[str, str]:
    results = {}

    for uploaded_file in uploaded_files:
        content = await uploaded_file.read()
        results[
            uploaded_file.filename
            or "unnamed"
        ] = hashlib.sha256(
            content
        ).hexdigest()

    return results
