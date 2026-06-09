def build_permission_context(
    verified_scopes: list[str],
    payload: dict,
) -> dict:
    context = {
        "scopes": verified_scopes,
    }
    # CWE-349 Fix: Prevent untrusted 'payload' from overwriting trusted keys
    # (specifically 'scopes' in this case) or injecting other sensitive,
    # unintended data into the context dictionary.
    # We create a new dictionary from the payload, excluding the 'scopes' key,
    # ensuring that the verified_scopes remain authoritative.
    safe_payload = {k: v for k, v in payload.items() if k != "scopes"}
    context.update(
        safe_payload
    )

    return context
