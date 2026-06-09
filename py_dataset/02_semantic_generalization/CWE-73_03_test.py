from pathlib import Path

from fastapi import FastAPI

app = FastAPI()


@app.post("/api/export")
async def export_csv(
    payload: dict,
) -> dict:
    target = Path(
        str(payload["output_path"])
    )
    target.write_text(
        render_csv(
            payload["rows"]
        ),
        encoding="utf-8",
    )

    return {
        "path": str(target),
    }
