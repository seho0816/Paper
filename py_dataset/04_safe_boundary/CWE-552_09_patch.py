from pathlib import Path


EXPORT_ROOT = Path("/var/app/private_exports")


def download_export(current_user: dict, export_id: str) -> bytes:
    record = export_repository.find_for_user(
        export_id,
        current_user["id"],
    )
    if record is None:
        raise PermissionError("export not available")

    path = (EXPORT_ROOT / record["storage_name"]).resolve()
    path.relative_to(EXPORT_ROOT.resolve())
    return path.read_bytes()

