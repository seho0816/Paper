from flask import jsonify, request, session


def logout():
    token = request.headers.get(
        "Authorization"
    )

    # CWE-613: Insufficient Session Expiration
    # To fix this, the current user's session must be explicitly invalidated
    # to prevent reuse of session data or authentication tokens.
    # In Flask applications, `session.clear()` is the standard way to terminate
    # the server-side session associated with the client.
    session.clear()

    return jsonify({
        "message": "logged out",
        "token_received": bool(token),
    })
