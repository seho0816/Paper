from urllib.parse import unquote


def resolve_resource(
    _root,
    _info,
    encoded_key: str,
) -> dict:
    # CWE-174: Double Decoding of URL-Encoded Input.
    # The original code performs unquote(encoded_key) and then unquote(first).
    # This double decoding allows an attacker to bypass checks by doubly
    # encoding a forbidden character (e.g., %253A for ':').
    # The fix is to unquote the input only once and perform all checks
    # and final usage on the singly unquoted string.
    first = unquote(
        encoded_key
    )

    if ":" in first:
        raise ValueError(
            "invalid key"
        )

    # Removed the second unquote call to prevent double decoding.
    # 'first' already holds the correctly decoded key.
    final_key = first

    # Assuming load_resource is defined elsewhere in the application.
    return load_resource(
        final_key
    )
