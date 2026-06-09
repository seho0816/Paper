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
        return web.json_response(
            {
                "error": str(error),
                "trace": traceback.format_exc(),
            },
            status=500,
        )
