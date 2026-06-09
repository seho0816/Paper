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
    current_user_id = request.headers.get(
        "X-User-Id",
        "",
    )
    order = orders.get(order_id)

    if (
        order is None
        or order["owner_id"] != current_user_id
    ):
        return jsonify({
            "error": "order not accessible",
        }), 404

    return jsonify(order)
