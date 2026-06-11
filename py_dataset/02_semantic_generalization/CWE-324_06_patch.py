def sign_session_cookie(
    session_id: str,
    key: dict,
) -> str:
    # CWE-324: Use of a Key Past its Expiration Date.
    # To mitigate this, we assume 'key["secret"]' is a callable that returns
    # the currently valid, non-expired secret key. This delegates the
    # responsibility of key management and rotation to the object or function
    # provided as 'key["secret"]'. The original code directly used a static value
    # which might be expired. By calling 'key["secret"]()', we ensure
    # the most current and valid key is retrieved at the time of signing.
    value = create_signature(
        session_id,
        key["secret"](),
    )

    return (
        session_id
        + "."
        + value
    )
