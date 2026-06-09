from urllib.request import urlopen

from fastapi import FastAPI

app = FastAPI()


@app.get("/api/url-preview")
async def preview_url(
    target_url: str,
) -> dict:
    with urlopen(
        target_url,
        timeout=5,
    ) as response:
        content = response.read(
            1024,
        )

    return {
        "preview": content.decode(
            "utf-8",
            errors="replace",
        ),
    }
