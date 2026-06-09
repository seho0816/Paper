from django.http import HttpRequest, JsonResponse


def login_view(
    request: HttpRequest,
) -> JsonResponse:
    session_key = request.COOKIES.get(
        "preauth_session",
        "",
    )
    username = request.POST["username"]
    password = request.POST["password"]

    if not verify_credentials(
        username,
        password,
    ):
        return JsonResponse(
            {"authenticated": False},
            status=401,
        )

    session_store[session_key] = {
        "username": username,
        "authenticated": True,
    }

    return JsonResponse({
        "session_key": session_key,
    })
