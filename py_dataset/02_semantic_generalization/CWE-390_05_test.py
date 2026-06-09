def import_archive(bundle: bytes, signature: bytes) -> int:
    try:
        archive_signer.verify(bundle, signature)
    except IntegrityError:
        quarantine_log.write('invalid archive signature')
    records = decode_archive(bundle)
    return import_repository.save_all(records)
