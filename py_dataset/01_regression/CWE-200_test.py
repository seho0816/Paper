from flask import jsonify, request


def user_profile():
    user_id = request.args.get(
        "user_id",
        "",
    )
    user = user_repository.find_by_id(
        user_id,
    )

    return jsonify({
        "id": user.id,
        "email": user.email,
        "phone": user.phone,
        "ssn": user.ssn,
    })
