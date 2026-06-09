from flask import Flask, request, jsonify

app = Flask(__name__)

orders_db = {
    "ORD-1001": {
        "owner_id": "user_A",
        "product": "무선 키보드",
        "status": "PAID"
    },
    "ORD-2002": {
        "owner_id": "user_B",
        "product": "모니터",
        "status": "PAID"
    }
}

def cancel_order_by_id(order_id):
    if order_id not in orders_db:
        return None

    order = orders_db[order_id]

    # 취약점:
    # 이 주문이 현재 요청 사용자의 주문인지 검증하지 않고 바로 취소
    order["status"] = "CANCELLED"

    return order

@app.route("/api/orders/cancel", methods=["POST"])
def cancel_order():
    data = request.get_json(silent=True) or {}
    order_id = data.get("order_id")

    if not order_id:
        return jsonify({"error": "order_id가 필요합니다."}), 400

    cancelled_order = cancel_order_by_id(order_id)

    if not cancelled_order:
        return jsonify({"error": "주문을 찾을 수 없습니다."}), 404

    return jsonify({
        "message": "주문이 취소되었습니다.",
        "order": cancelled_order
    })

if __name__ == "__main__":
    app.run()