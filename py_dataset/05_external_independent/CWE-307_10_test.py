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
        return web.json_response(
            {"error": "invalid credentials"},
            status=401,
        )

    return web.json_response({
        "authenticated": True,
    })


app = web.Application()
app.router.add_post("/login", login)
