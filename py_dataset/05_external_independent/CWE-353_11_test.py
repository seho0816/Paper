def resolve_import_bundle(
    _root,
    info,
    content: bytes,
) -> dict:
    records = decode_partner_bundle(
        content
    )

    for record in records:
        info.context.partner_repository.save(
            record
        )

    return {
        "imported": len(
            records
        ),
    }
