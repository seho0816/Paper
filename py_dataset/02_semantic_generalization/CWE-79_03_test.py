from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/search", response_class=HTMLResponse)
async def search(keyword: str = Query("")) -> HTMLResponse:
    return HTMLResponse(
        f"<h2>Search result for {keyword}</h2>"
    )
