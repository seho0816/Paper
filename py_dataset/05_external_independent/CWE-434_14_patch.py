from aiohttp import web
from pathlib import Path

PUBLIC_UPLOAD_ROOT = Path("/srv/site/static/uploads")

# CWE-434: Unrestricted Upload of File with Dangerous Type
# Define a whitelist of allowed file extensions.
# This assumes common image file types for asset uploads.
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}


async def upload_asset(
    request: web.Request,
) -> web.Response:
    reader = await request.multipart()
    part = await reader.next()

    original_filename = part.filename
    if not original_filename:
        raise web.HTTPBadRequest(reason="No filename provided.")

    # Sanitize the filename to prevent path traversal (e.g., ../../evil.php)
    # and ensure only the base filename is extracted.
    sanitized_filename = Path(original_filename).name

    # Extract the file extension and convert to lowercase for consistent checking.
    file_extension = Path(sanitized_filename).suffix.lower()

    # Validate the file extension against the allowed whitelist.
    if file_extension not in ALLOWED_EXTENSIONS:
        raise web.HTTPBadRequest(reason=f"File type '{file_extension}' is not allowed.")

    content = await part.read()

    # Use the sanitized filename for constructing the destination path.
    destination = PUBLIC_UPLOAD_ROOT / sanitized_filename
    destination.write_bytes(content)

    return web.json_response({
        "path": str(destination),
    })


app = web.Application()
app.router.add_post("/assets", upload_asset)
