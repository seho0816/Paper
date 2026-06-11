import html
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/search", response_class=HTMLResponse)
async def search(keyword: str = Query("")) -> HTMLResponse:
    # CWE-79: Input is escaped to prevent Cross-Site Scripting (XSS).
    # html.escape() converts characters like <, >, &, ", ' into their HTML-safe entities.
    sanitized_keyword = html.escape(keyword)
    return HTMLResponse(
        f"<h2>Search result for {sanitized_keyword}</h2>"
    )
