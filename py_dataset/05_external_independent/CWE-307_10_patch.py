import asyncio
from aiohttp import web


async def login(
    request: web.Request,
) -> web.Response:
    payload = await request.json()
    username = str(payload["username"])
    password = str(payload["password"])

    if not verify_credentials(
        username,
        password,
    ):
        # CWE-307 mitigation: Introduce a delay for failed login attempts.
        # This makes brute-force attacks significantly less efficient.
        # A more robust solution might involve tracking failed attempts per user/IP
        # and increasing the delay or temporarily locking the account/IP.
        await asyncio.sleep(2)

        return web.json_response(
            {"error": "invalid credentials"},
            status=401,
        )

    return web.json_response({
        "authenticated": True,
    })


app = web.Application()
app.router.add_post("/login", login)
