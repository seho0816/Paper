from pathlib import Path


SHARED_SECRETS = Path('/srv/shared/secrets')


def save_partner_secret(
    partner_id: str,
    secret: str,
) -> Path:
    target = SHARED_SECRETS / f'{partner_id}.txt'
    with target.open(
        'w',
        encoding='utf-8',
    ) as output:
        output.write(secret)
    return target
