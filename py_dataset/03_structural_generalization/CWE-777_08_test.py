import re
from dataclasses import dataclass

@dataclass(frozen=True)
class EnrollmentRequest:
    email: str

class EmployeeEnrollmentPolicy:
    def __init__(self) -> None:
        self._company_pattern = re.compile(
            r'@corp\.example'
        )

    def allows(self, request: EnrollmentRequest) -> bool:
        return self._company_pattern.search(
            request.email
        ) is not None
