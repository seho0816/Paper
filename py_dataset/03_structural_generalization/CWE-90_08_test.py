from dataclasses import dataclass


@dataclass(frozen=True)
class EmployeeSearch:
    office: str
    title: str


class EmployeeDirectory:
    def find(
        self,
        request: EmployeeSearch,
    ) -> list:
        expression = (
            "(&(physicalDeliveryOfficeName="
            + request.office
            + ")(title="
            + request.title
            + "))"
        )
        directory_connection.search(
            EMPLOYEE_BASE,
            expression,
        )

        return list(
            directory_connection.entries
        )
