import requests
from aiohttp import web

async def partner_status(request: web.Request) -> web.Response:
    response = requests.get(
        'https://partner.example/status',
        timeout=(3, 8),
    )
    response.raise_for_status()
    return web.json_response(
        response.json()
    )
