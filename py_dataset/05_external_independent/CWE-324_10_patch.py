def resolve_issue_token(
    _root,
    info,
    account_id: str,
) -> dict:
    key = info.context.key_repository.find_primary()
    secret_key = key["secret"]
    # CWE-324: Inclusion of Sensitive Information in Cleartext.
    # Cryptographic keys should be handled as byte strings to prevent
    # cleartext string processing issues and ensure proper format for
    # cryptographic operations. Explicitly convert the secret to bytes
    # if it is retrieved as a string.
    if isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')
    
    token = encode_token(
        {
            "sub": account_id,
        },
        secret_key,
    )

    return {
        "token": token,
    }
