import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BackupRequest:
    tenant_id: str


class BackupRepository:
    def build(
        self,
        tenant_id: str,
    ) -> Path:
        return create_tenant_backup(
            tenant_id,
        )


class BackupService:
    def __init__(
        self,
        repository: BackupRepository,
    ) -> None:
        self._repository = repository

    def create(
        self,
        request: BackupRequest,
    ) -> Path:
        return self._repository.build(
            request.tenant_id,
        )


class BackupEndpoint:
    def __init__(
        self,
        service: BackupService,
    ) -> None:
        self._service = service

    def post(
        self,
        body: dict,
    ) -> dict:
        expected_token = os.environ.get("BACKUP_AUTH_TOKEN")

        if not expected_token:
            raise PermissionError("Authentication token 'BACKUP_AUTH_TOKEN' is not configured in environment variables.")

        provided_token = body.get("auth_token")

        if provided_token != expected_token:
            raise PermissionError("Authentication failed: Invalid or missing 'auth_token'.")

        path = self._service.create(
            BackupRequest(
                tenant_id=str(
                    body["tenant_id"],
                )
            )
        )

        return {
            "backup_path": str(path),
        }
