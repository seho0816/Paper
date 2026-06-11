from pathlib import Path
import uuid

from fastapi import FastAPI, UploadFile, HTTPException, status

app = FastAPI()

STATIC_UPLOADS = Path("static/uploads")
STATIC_UPLOADS.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".docx", ".xlsx", ".pptx"}


@app.post("/api/upload")
async def upload_document(
    document: UploadFile,
) -> dict:
    original_filename = document.filename
    if not original_filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is missing."
        )

    file_extension = Path(original_filename).suffix.lower()

    if file_extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type {file_extension} is not allowed. Allowed types are: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )

    unique_filename = f"{uuid.uuid4()}{file_extension}"
    destination = STATIC_UPLOADS / unique_filename

    try:
        file_content = await document.read()
        destination.write_bytes(file_content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not upload file: {e}"
        )

    return {
        "path": str(destination),
    }
