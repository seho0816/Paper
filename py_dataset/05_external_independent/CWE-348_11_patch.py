import os

def resolve_send_verification(
    _root,
    info,
    email: str,
) -> dict:
    # The 'Host' header is user-controlled and should not be used directly
    # to construct links sent to users, as it can lead to host header injection
    # vulnerabilities (e.g., phishing, cache poisoning).
    # Instead, a trusted application domain should be used from configuration.
    # We retrieve the trusted host from an environment variable.
    
    # OLD: host = info.context.headers.get("Host")
    
    host = os.environ["APP_DOMAIN"] # Use a trusted domain from configuration
    
    token = create_verification_token(
        email
    )
    link = (
        f"https://{host}/verify"
        f"?token={token}"
    )
    send_email(
        email,
        link,
    )

    return {
        "sent": True,
    }
