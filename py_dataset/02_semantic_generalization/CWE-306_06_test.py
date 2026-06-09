def download_audit_bundle(
    request: dict,
) -> bytes:
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
