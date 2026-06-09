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
        # CWE-777: Polymorphic Typing
        # Ensure that request.email is strictly a string type at runtime.
        # This prevents unexpected behavior or potential vulnerabilities
        # if a non-string object with an overridden __str__ method or
        # an expensive string conversion operation is passed.
        if not isinstance(request.email, str):
            raise TypeError("Email attribute of EnrollmentRequest must be a string.")

        return self._company_pattern.search(
            request.email
        ) is not None
