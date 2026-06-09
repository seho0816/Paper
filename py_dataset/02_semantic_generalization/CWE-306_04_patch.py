import os
from aiohttp import web


async def clear_application_cache(
    request: web.Request,
) -> web.Response:
    try:
        # Retrieve the API key from environment variables.
        # This key must be securely configured in the environment for authentication to work.
        # Example: export SECRET_ADMIN_KEY="your_actual_super_secret_key_here"
        expected_api_key = os.environ["SECRET_ADMIN_KEY"]
    except KeyError:
        # If the SECRET_ADMIN_KEY environment variable is not set,
        # the server is misconfigured to perform authentication for this critical function.
        # This should prevent any access to protect against CWE-306.
        return web.json_response(
            {"error": "Server configuration error: SECRET_ADMIN_KEY environment variable not set."},
            status=500  # Internal Server Error due to misconfiguration
        )

    # Get the API key from the 'X-API-Key' request header.
    # Clients attempting to clear the cache must provide this header
    # with the correct secret key.
    provided_api_key = request.headers.get("X-API-Key")

    # Perform authentication: Check if an API key was provided and if it matches the expected key.
    if not provided_api_key or provided_api_key != expected_api_key:
        # If authentication fails, return a 401 Unauthorized response.
        return web.json_response(
            {"error": "Authentication required or invalid API key provided."},
            status=401  # Unauthorized
        )

    # If authentication succeeds, proceed with the critical operation.
    # The 'cache' object is assumed to be globally available or imported elsewhere,
    # as per the original code's context.
    await cache.clear()

    return web.json_response({
        "cleared": True,
    })


app = web.Application()
app.router.add_post(
    "/internal/cache/clear",
    clear_application_cache,
)
