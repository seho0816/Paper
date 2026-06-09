import zipfile
from pathlib import Path


IMPORT_ROOT = Path(
    "/var/app/imported"
)


def import_partner_bundle(
    bundle_path: str,
) -> list[str]:
    imported = []

    with zipfile.ZipFile(
        bundle_path
    ) as bundle:
        for name in bundle.namelist():
            data = bundle.read(
                name
            )
            target = (
                IMPORT_ROOT
                / name
            )
            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            target.write_bytes(
                data
            )
            imported.append(
                name
            )

    return imported
