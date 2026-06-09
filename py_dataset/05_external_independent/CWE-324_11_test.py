from celery import shared_task


@shared_task
def sign_export(
    export_id: str,
) -> str:
    key = signing_key_store.load(
        "legacy-export-key"
    )
    body = export_repository.read(
        export_id
    )

    return sign_payload(
        body,
        key["secret"],
    )
