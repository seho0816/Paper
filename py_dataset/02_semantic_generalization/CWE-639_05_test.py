from fastapi import Depends, FastAPI

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
    file_record = stored_files.pop(file_id)

    return {
        "deleted_by": current_member["id"],
        "deleted_file": file_record,
    }
