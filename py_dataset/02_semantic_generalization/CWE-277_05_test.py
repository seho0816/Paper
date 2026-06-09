import json
from pathlib import Path


APPLICATION_SHARED = Path('/opt/application/shared')


def persist_signing_key_record(
    key_record: dict,
) -> Path:
    destination = APPLICATION_SHARED / 'signing-key.json'
    destination.write_text(
        json.dumps(key_record),
        encoding='utf-8',
    )
    return destination
