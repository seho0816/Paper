from fastapi import Depends, FastAPI, HTTPException

app = FastAPI()

stored_files = {
    "file-11": {
        "owner_id": "member-1",
        "path": "/data/member-1/report.pdf",
    },
    "file-22": {
        "owner_id": "member-2",
        "path": "/data/member-2/report.pdf",
    },
}


def get_current_member() -> dict:
    return {
        "id": "member-1",
    }


@app.delete("/api/files/{file_id}")
async def delete_file(
    file_id: str,
    current_member: dict = Depends(
        get_current_member,
    ),
) -> dict:
    # CWE-639: Authorization Bypass Through User-Controlled Key
    # Vulnerability: The original code directly called stored_files.pop(file_id)
    # without checking if the current_member is authorized to delete the file.
    # Fix: Add a check to ensure the file exists and the current member is its owner
    # before attempting to delete it.

    if file_id not in stored_files:
        raise HTTPException(status_code=404, detail="File not found")

    file_record_to_check = stored_files[file_id]

    if file_record_to_check["owner_id"] != current_member["id"]:
        raise HTTPException(status_code=403, detail="Not authorized to delete this file")

    file_record = stored_files.pop(file_id)

    return {
        "deleted_by": current_member["id"],
        "deleted_file": file_record,
    }
