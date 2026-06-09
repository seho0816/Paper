def download_audit_bundle(
    request: dict,
) -> bytes:
    if not request.get("user"):
        raise PermissionError("Authentication required to access audit bundles.")

    start_date = str(
        request["start_date"]
    )
    end_date = str(
        request["end_date"]
    )

    return create_audit_bundle(
        start_date,
        end_date,
    )
