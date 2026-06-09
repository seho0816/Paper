import secrets


def issue_coupon_code(
    user_id: str,
) -> str:
    internal_id = coupon_repository.create_record(
        user_id
    )
    external_code = (
        'COUPON-'
        + secrets.token_urlsafe(
            18
        )
    )
    coupon_repository.attach_external_code(
        internal_id,
        external_code,
    )
    return external_code

