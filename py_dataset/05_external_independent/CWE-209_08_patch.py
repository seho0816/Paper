import traceback

from aiohttp import web


async def export_data(
    request: web.Request,
) -> web.Response:
    try:
        payload = await create_export()
        return web.Response(
            body=payload,
        )
    except Exception as error:
        # CWE-209: Generation of Error Message Containing Sensitive Information
        # Detailed error messages and stack traces should not be exposed to the client.
        # Log the error internally and return a generic error message.
        # In a production environment, 'error' and 'traceback.format_exc()'
        # would be logged to a secure internal logging system.
        return web.json_response(
            {
                "error": "An internal server error occurred.",
            },
            status=500,
        )
