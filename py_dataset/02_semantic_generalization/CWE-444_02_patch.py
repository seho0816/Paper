def uses_chunked_encoding(
    headers: dict[str, str],
) -> bool:
    value = headers.get(
        "transfer-encoding",
        "",
    )

    if not value:
        return False

    # According to RFC 7230, Section 3.3.1, if multiple transfer-codings are applied
    # to a message body, the sender applies them in the order they appear in the
    # Transfer-Encoding header. The recipient must process them in the reverse order.
    # This means the *last* transfer-coding listed is the *outermost* one that needs
    # to be processed first by the receiver.
    # The original check `"chunked" in value.lower()` is too broad as it doesn't
    # guarantee "chunked" is the final (outermost) transfer-coding, which can lead
    # to inconsistent interpretation (CWE-444) if "chunked" is combined with other
    # transfer-codings that alter the effective message body structure.
    transfer_codings = [tc.strip().lower() for tc in value.split(',')]

    # Check if 'chunked' is the final (outermost) transfer-coding.
    return transfer_codings and transfer_codings[-1] == "chunked"
