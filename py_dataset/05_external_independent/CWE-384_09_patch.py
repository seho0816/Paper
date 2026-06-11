import secrets
from django.http import HttpRequest, JsonResponse


def login_view(
    request: HttpRequest,
) -> JsonResponse:
    # 1. Get the existing (potentially attacker-controlled) session key from cookies.
    old_session_key = request.COOKIES.get(
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

    # CWE-384 Fix: Invalidate the old session and generate a new one upon successful authentication.
    # 2. If an old session key existed and was valid in our store, remove it to invalidate.
    #    (Assumes 'session_store' is a dictionary or similar lookup structure).
    if old_session_key and old_session_key in session_store:
        del session_store[old_session_key]

    # 3. Generate a new, cryptographically secure session key.
    new_session_key = secrets.token_urlsafe(32)

    # 4. Store the authenticated session data using the new session key.
    session_store[new_session_key] = {
        "username": username,
        "authenticated": True,
    }

    # 5. Create the JSON response indicating success and returning the new session key.
    response = JsonResponse({
        "session_key": new_session_key,
    })

    # 6. Set the new session key as a secure HTTP-only cookie.
    #    'httponly=True' prevents client-side scripts from accessing the cookie.
    #    'secure=True' ensures the cookie is only sent over HTTPS.
    #    'samesite="Lax"' helps mitigate CSRF risks.
    response.set_cookie(
        "preauth_session",
        new_session_key,
        httponly=True,
        secure=True,
        samesite="Lax",
    )

    return response
