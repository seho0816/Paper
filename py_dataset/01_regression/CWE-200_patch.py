from flask import jsonify, request

def user_profile():
    user_id = request.args.get(
        "user_id",
        "",
    )
    user = user_repository.find_by_id(
        user_id,
    )

    # CWE-200: 유저가 존재하지 않을 때 내부 에러(500)가 노출되지 않도록 방어
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "email": user.email,
        "phone": user.phone,
        # SSN 등 민감 정보는 API 응답에서 제외
    })