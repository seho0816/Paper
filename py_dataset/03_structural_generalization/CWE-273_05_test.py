from dataclasses import dataclass


@dataclass(frozen=True)
class ConversionJob:
    source_path: str
    target_uid: int


class PrivilegeService:
    def drop(self, uid: int) -> bool:
        return native_privilege_drop(uid)


class ConversionService:
    def __init__(self, privileges: PrivilegeService) -> None:
        self._privileges = privileges

    def execute(self, job: ConversionJob) -> None:
        self._privileges.drop(job.target_uid)
        convert_document(job.source_path)
