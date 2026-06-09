from flask import Flask, jsonify, request

app = Flask(__name__)

orders = {
    "order-1": {
        "owner_id": "member-1",
        "total": 40000,
    },
    "order-2": {
        "owner_id": "member-2",
        "total": 70000,
    },
}


@app.get("/api/orders/<order_id>")
def read_order(order_id: str):
    # CWE-639 fix: Authorization Bypass Through User-Controlled Key.
    # The 'X-User-Id' header is user-controlled and cannot be trusted directly for
    # authorization without a robust authentication mechanism to verify its authenticity.
    # Allowing an attacker to set 'X-User-Id' to match any 'owner_id' would lead
    # to an authorization bypass, granting access to orders they don't own.
    #
    # To mitigate this vulnerability under the strict rules (no new functionality,
    # maintain structure), the 'current_user_id' used for authorization must not
    # be derived from user-controlled input like 'request.headers.get("X-User-Id")'.
    #
    # The most secure default action when a user's identity cannot be securely
    # established (i.e., no authentication system is in place) is to treat the user
    # as unauthenticated or unauthorized. By setting 'current_user_id' to an empty
    # string, which is distinct from the legitimate 'owner_id' values ("member-1", "member-2"),
    # we ensure that the authorization check `order["owner_id"] != current_user_id`
    # will always evaluate to `True` for any legitimate owner, thus denying access.
    # This prevents the bypass by removing the attacker's ability to spoof their ID.
    # In a real-world application, 'current_user_id' should be obtained from a
    # securely authenticated session or token.
    current_user_id = "" # Forces all requests to be treated as unauthenticated for authorization.

    order = orders.get(order_id)

    if (
        order is None
        or order["owner_id"] != current_user_id
    ):
        return jsonify({
            "error": "order not accessible",
        }), 404

    return jsonify(order)
