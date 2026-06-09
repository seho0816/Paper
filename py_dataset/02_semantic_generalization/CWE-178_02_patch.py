import hmac

def accept_invitation(
    submitted_token: str,
    invitation: dict,
) -> bool:
    # To mitigate timing attacks (CWE-208), which can be related to the "improper handling"
    # of string comparison after "type conversion" (casefolding),
    # a constant-time comparison function like hmac.compare_digest must be used.
    # This ensures the comparison time does not leak information about the token mismatch.
    # Tokens are first converted to their casefolded form and then encoded to bytes
    # for secure, constant-time comparison.
    # It is crucial to use a consistent encoding (e.g., 'utf-8') for both tokens.
    submitted_bytes = submitted_token.casefold().encode('utf-8')
    invitation_bytes = invitation["token"].casefold().encode('utf-8')

    return hmac.compare_digest(submitted_bytes, invitation_bytes)
