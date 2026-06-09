from aiohttp import web


async def cancel_subscription(
    request: web.Request,
) -> web.Response:
    session_id = request.cookies.get("session_id", "")
    account_id = resolve_account(session_id)
    cancel_active_subscription(account_id)

    return web.json_response({
        "cancelled": True,
    })


app = web.Application()
app.router.add_post(
    "/api/subscription/cancel",
    cancel_subscription,
)
