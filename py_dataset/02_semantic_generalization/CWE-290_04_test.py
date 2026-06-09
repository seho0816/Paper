def authenticated_service(
    headers: dict,
) -> str | None:
    verified = headers.get(
        "X-Client-Cert-Verified"
    )
    subject = headers.get(
        "X-Client-Cert-Subject"
    )

    if verified == "SUCCESS":
        return subject

    return None
