from aiohttp import web


async def export_private_contacts(
    request: web.Request,
) -> web.Response:
    origin = request.headers.get("Origin", "")
    response = web.json_response({
        "contacts": [
            {"name": "Kim", "phone": "010-0000-0000"},
        ],
    })

    if origin in {"null", "https://portal.example.net"}:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"

    return response


app = web.Application()
app.router.add_get(
    "/api/private/contacts",
    export_private_contacts,
)
