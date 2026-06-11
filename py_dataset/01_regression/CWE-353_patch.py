import zipfile
from pathlib import Path


IMPORT_ROOT = Path(
    "/var/app/imported"
)


def import_partner_bundle(
    bundle_path: str,
) -> list[str]:
    imported = []

    # Resolve the import root to its canonical path to prevent path traversal via symlinks
    # or obscure directory references.
    resolved_import_root = IMPORT_ROOT.resolve()

    with zipfile.ZipFile(
        bundle_path
    ) as bundle:
        for name in bundle.namelist():
            data = bundle.read(
                name
            )
            # Construct the full target path. pathlib's / operator handles simple '..' and '.'
            # components safely within the path structure.
            target = (
                IMPORT_ROOT
                / name
            )

            # Resolve the target path to its canonical form, handling any '..' sequences
            # or symbolic links. Use strict=False to allow paths that may not exist yet.
            resolved_target = target.resolve(strict=False)

            # Crucial security check: Ensure the resolved target path is strictly
            # within the resolved import root directory. If not, it's a path traversal attempt.
            if not resolved_target.is_relative_to(resolved_import_root):
                # Skip files attempting to escape the intended directory.
                continue

            # Ensure the parent directory exists for the target path.
            # This mkdir operates on `target.parent`, which after the `is_relative_to` check,
            # is guaranteed to resolve to a safe location within `IMPORT_ROOT`.
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
