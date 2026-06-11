from flask import request, jsonify

# [PATCH CWE-915] Mass Assignment 방지:
# 사용자가 수정할 수 있는 필드를 명시적으로 허용 목록(allowlist)으로 제한.
BOOKING_ALLOWED_FIELDS = {'guest_name', 'check_in_date', 'check_out_date', 'special_requests'}

@app.route('/api/booking/update', methods=['POST'])
def update_booking():
    booking = get_booking(request.json['id'])

    for key, value in request.json.items():
        # [PATCH] setattr(booking, key, value) 는 'price', 'status', 'is_paid' 등
        # 민감한 내부 속성까지 공격자가 임의로 덮어쓸 수 있는 취약점.
        # 허용된 필드만 업데이트함.
        if key in BOOKING_ALLOWED_FIELDS:
            setattr(booking, key, value)

    save_booking(booking)
    return jsonify(booking)