from flask import jsonify, request


def logout():
    token = request.headers.get(
        "Authorization"
    )

    return jsonify({
        "message": "logged out",
        "token_received": bool(token),
    })
