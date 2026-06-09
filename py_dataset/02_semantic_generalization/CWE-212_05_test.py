def build_backup_manifest(service: dict, files: list[str]) -> dict:
    return {
        "service": service,
        "files": files,
        "created_by": "backup-worker",
    }
