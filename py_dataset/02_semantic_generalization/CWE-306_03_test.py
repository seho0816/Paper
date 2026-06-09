from fastapi import FastAPI
from fastapi.responses import StreamingResponse

app = FastAPI()


@app.get("/api/admin/users/export")
async def export_users():
    export_stream = generate_user_export()

    return StreamingResponse(
        export_stream,
        media_type="text/csv",
    )
