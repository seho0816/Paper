from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExportRequest:
    destination: Path
    content: bytes


class ExportRepository:
    def exists(
        self,
        path: Path,
    ) -> bool:
        return path.exists()

    def save(
        self,
        request: ExportRequest,
    ) -> None:
        # CWE-367: Improper Link Resolution Before File Access ('Time-of-check Time-of-use' Race Condition)
        # To fix the TOCTOU vulnerability when creating a file,
        # use an atomic operation that checks for existence and creates the file exclusively.
        # Path.open(mode='xb') achieves this by raising FileExistsError if the file already exists.
        try:
            with request.destination.open(mode='xb') as f:
                f.write(request.content)
        except FileExistsError:
            # Re-raise FileExistsError with the path to maintain consistent error message
            # as intended by the ExportService.create method's original behavior.
            raise FileExistsError(request.destination)


class ExportService:
    def __init__(
        self,
        repository: ExportRepository,
    ) -> None:
        self._repository = repository

    def create(
        self,
        request: ExportRequest,
    ) -> None:
        # CWE-367: Improper Link Resolution Before File Access ('Time-of-check Time-of-use' Race Condition)
        # The original check `if self._repository.exists(...)` followed by `_repository.save(...)`
        # created a TOCTOU race condition. An attacker could create a symlink in between the check and use.
        #
        # The fix is to remove the non-atomic check here and rely on the
        # atomic exclusive creation provided by _repository.save() (using open(mode='xb')),
        # which will raise FileExistsError if the file already exists.
        # This ensures the file existence check and creation are a single, atomic operation.
        self._repository.save(
            request
        )
