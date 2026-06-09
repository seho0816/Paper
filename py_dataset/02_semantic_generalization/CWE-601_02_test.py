from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse

app = FastAPI()


@app.get("/continue")
async def continue_flow(
    next_url: str = Query("/"),
) -> RedirectResponse:
    return RedirectResponse(
        next_url,
        status_code=302,
    )
