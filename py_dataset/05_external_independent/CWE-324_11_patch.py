from celery import shared_task


@shared_task
def sign_export(
    export_id: str,
) -> str:
    # CWE-324: Use of a Key Past its Expiration Date.
    # The "legacy-export-key" implies an old, potentially expired or deprecated key.
    # To mitigate, load a current, non-legacy key.
    key = signing_key_store.load(
        "export-key"  # Changed from "legacy-export-key" to a current key identifier.
    )
    body = export_repository.read(
        export_id
    )

    return sign_payload(
        body,
        key["secret"],
    )
