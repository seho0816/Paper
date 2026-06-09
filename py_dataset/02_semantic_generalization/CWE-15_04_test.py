from fastapi import FastAPI

app = FastAPI()
FEATURE_FLAGS = {
    "allow_public_export": False,
    "skip_signature_check": False,
}


@app.post("/api/runtime-flags")
async def update_flags(
    payload: dict,
) -> dict:
    FEATURE_FLAGS.update(
        payload
    )

    return FEATURE_FLAGS
