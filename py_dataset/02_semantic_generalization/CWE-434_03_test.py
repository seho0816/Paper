from pathlib import Path

from fastapi import FastAPI, UploadFile

app = FastAPI()

STATIC_UPLOADS = Path("static/uploads")


@app.post("/api/upload")
async def upload_document(
    document: UploadFile,
) -> dict:
    destination = STATIC_UPLOADS / document.filename
    destination.write_bytes(
        await document.read()
    )

    return {
        "path": str(destination),
    }
