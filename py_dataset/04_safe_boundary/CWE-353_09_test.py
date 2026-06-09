def import_partner_bundle(
    bundle_body: bytes,
    signature: bytes,
    trusted_public_key,
) -> int:
    trusted_public_key.verify(
        signature,
        bundle_body,
    )
    records = decode_partner_bundle(
        bundle_body
    )

    with partner_repository.transaction():
        for record in records:
            partner_repository.save(
                record
            )

    return len(
        records
    )
