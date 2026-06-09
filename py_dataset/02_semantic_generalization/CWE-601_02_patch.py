from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse
import urllib.parse

app = FastAPI()


@app.get("/continue")
async def continue_flow(
    next_url: str = Query("/"),
) -> RedirectResponse:
    parsed_url = urllib.parse.urlparse(next_url)

    # Validate that the next_url is a relative path to prevent Open Redirect (CWE-601).
    # If the URL has a scheme (e.g., http, https, javascript) or a network location (domain),
    # it is considered an external or potentially malicious URL.
    if parsed_url.scheme or parsed_url.netloc:
        # Redirect to a safe default path if the provided URL is external.
        safe_redirect_url = "/"
    else:
        # Otherwise, if it's a relative path, use it.
        # Ensure the path part is used, not queries or fragments from an invalid 'relative' URL.
        # This prevents cases like next_url="///example.com" which urlparse might treat as relative path but with a netloc.
        # However, parsed_url.scheme or parsed_url.netloc already covers this.
        # The path itself should be clean if scheme and netloc are empty.
        safe_redirect_url = parsed_url.path
        if parsed_url.query:
            safe_redirect_url += "?" + parsed_url.query
        if parsed_url.fragment:
            safe_redirect_url += "#" + parsed_url.fragment

    return RedirectResponse(
        safe_redirect_url,
        status_code=302,
    )
