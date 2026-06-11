from pathlib import Path


GROUP_STORAGE = Path('/srv/group-storage')
CREDENTIAL_DIRECTORY = GROUP_STORAGE / 'credentials'


def prepare_credential_directory() -> Path:
    CREDENTIAL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )
    return CREDENTIAL_DIRECTORY
