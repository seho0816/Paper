import requests
import aiohttp
from aiohttp import web

async def partner_status(request: web.Request) -> web.Response:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            'https://partner.example/status',
            timeout=aiohttp.ClientTimeout(connect=3, sock_read=8),
        ) as response:
            response.raise_for_status()
            data = await response.json()
            return web.json_response(data)
