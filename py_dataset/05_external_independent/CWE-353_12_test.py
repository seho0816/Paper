from celery import shared_task


@shared_task
def import_partner_snapshot(
    snapshot_body: bytes,
) -> int:
    records = parse_partner_snapshot(
        snapshot_body
    )

    for record in records:
        partner_repository.save(
            record
        )

    return len(
        records
    )
