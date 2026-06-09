import os
from pathlib import Path


SHARED_SECRETS = Path('/srv/shared/secrets')


def save_partner_secret(
    partner_id: str,
    secret: str,
) -> Path:
    target = SHARED_SECRETS / f'{partner_id}.txt'

    original_umask = os.umask(0o077)
    try:
        with target.open(
            'w',
            encoding='utf-8',
        ) as output:
            output.write(secret)
    finally:
        os.umask(original_umask)
        
    return target
