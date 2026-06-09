from urllib.parse import unquote


def resolve_route_key(
    raw_key: str,
) -> str:
    # Decode the input only once. All subsequent checks and operations
    # should be performed on this singly-decoded string to prevent CWE-174
    # (Double Decoding of URL-Encoded Input).
    decoded_key = unquote(raw_key)

    if "/" in decoded_key:
        raise ValueError(
            "invalid key"
        )

    # Return the singly-decoded key. No further decoding is needed or safe.
    return decoded_key
