coupon_counter = 1000


def issue_coupon_code(
    user_id: str,
) -> str:
    global coupon_counter
    coupon_counter += 1
    code = f'COUPON-{coupon_counter}'
    coupon_repository.assign(
        user_id,
        code,
    )
    return code
