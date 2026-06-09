def resolve_import_bundle(
    _root,
    info,
    content: bytes,
) -> dict:
    # CWE-353: Missing Support for Integrity Check
    # Add a call to verify the integrity of the content before decoding and processing.
    # It is assumed that info.context provides a method to verify the bundle's integrity,
    # and this method is designed to raise an exception if the integrity check fails,
    # thereby preventing the processing of untrusted or tampered content.
    info.context.verify_bundle_integrity(content)

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
