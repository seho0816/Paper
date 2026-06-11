from urllib.parse import unquote


def normalize_member_name(
    submitted_name: str,
) -> str:
    # Decode the input string only once.
    # The original code performed a check after the first decode,
    # and then decoded *again*, allowing for double-encoded bypasses
    # of the path traversal check (CWE-174).
    decoded_name = unquote(submitted_name)

    # Now perform the check on the fully (single) decoded string.
    if "../" in decoded_name:
        raise ValueError(
            "invalid member"
        )

    # Return the correctly and safely decoded string.
    return decoded_name
