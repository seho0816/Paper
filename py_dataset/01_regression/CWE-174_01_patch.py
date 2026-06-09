from urllib.parse import unquote


def build_redirect(
    raw_target: str,
) -> str:
    first = unquote(
        raw_target
    )

    # The original code performs a check after the first unquote
    # but then implicitly performs a second unquote in the return statement.
    # The vulnerability (CWE-174) arises because the check is not applied
    # to the *fully* decoded string, allowing double-encoded malicious URLs to bypass it.
    # To fix this, we apply the second unquote first, and then perform the check.
    fully_decoded_target = unquote(
        first
    )

    if fully_decoded_target.startswith(
        "http://"
    ):
        raise ValueError(
            "external target"
        )

    return fully_decoded_target
