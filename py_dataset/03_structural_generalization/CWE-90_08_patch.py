from dataclasses import dataclass
from ldap3.utils.conv import escape_filter_chars


@dataclass(frozen=True)
class EmployeeSearch:
    office: str
    title: str


class EmployeeDirectory:
    def find(
        self,
        request: EmployeeSearch,
    ) -> list:
        # CWE-90 fix: Escape special characters in user-provided input
        # to prevent LDAP injection.
        escaped_office = escape_filter_chars(request.office)
        escaped_title = escape_filter_chars(request.title)

        expression = (
            "(&(physicalDeliveryOfficeName="
            + escaped_office
            + ")(title="
            + escaped_title
            + "))"
        )
        directory_connection.search(
            EMPLOYEE_BASE,
            expression,
        )

        return list(
            directory_connection.entries
        )
