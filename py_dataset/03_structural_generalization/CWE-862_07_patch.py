from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DeletionRequest:
    actor_id: str
    path: Path


class FileAdministrationService:
    def delete(
        self,
        current_user: dict,
        requested_path: str,
    ) -> None:
        if current_user.get("role") != "admin":
            raise PermissionError("User not authorized to delete files.")

        command = DeletionRequest(
            actor_id=current_user["id"],
            path=Path(requested_path),
        )
        command.path.unlink()
