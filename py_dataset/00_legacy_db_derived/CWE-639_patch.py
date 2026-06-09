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

def get_current_user_id(request) -> str:
    """
    실제 구현에서는 JWT 토큰 또는 세션에서 현재 사용자 ID를 추출.
    여기서는 구조 시연용 스텁 함수.
    """
    return request.headers.get("X-User-Id", "")

def cancel_order_by_id(order_id, requesting_user_id):
    if order_id not in orders_db:
        return None, "not_found"

    order = orders_db[order_id]

    # [PATCH CWE-639] 객체 수준 인가(Object-Level Authorization) 검증 추가:
    # 요청한 사용자가 해당 주문의 소유자인지 반드시 확인.
    # order_id만 알면 누구의 주문이든 취소할 수 있던 취약점을 차단.
    if order["owner_id"] != requesting_user_id:
        return None, "forbidden"

    order["status"] = "CANCELLED"
    return order, "ok"

@app.route("/api/orders/cancel", methods=["POST"])
def cancel_order():
    data = request.get_json(silent=True) or {}
    order_id = data.get("order_id")

    if not order_id:
        return jsonify({"error": "order_id가 필요합니다."}), 400

    current_user_id = get_current_user_id(request)
    if not current_user_id:
        return jsonify({"error": "인증이 필요합니다."}), 401

    cancelled_order, status = cancel_order_by_id(order_id, current_user_id)

    if status == "not_found":
        return jsonify({"error": "주문을 찾을 수 없습니다."}), 404
    if status == "forbidden":
        return jsonify({"error": "본인의 주문만 취소할 수 있습니다."}), 403

    return jsonify({
        "message": "주문이 취소되었습니다.",
        "order": cancelled_order
    })

if __name__ == "__main__":
    app.run()
