from dataclasses import dataclass


# Assume create_database_client function exists and handles different roles.
# For example:
# def create_database_client(role: str):
#     if role == "admin":
#         # Return a client with admin privileges
#         pass
#     elif role == "reader":
#         # Return a client with read-only privileges
#         pass
#     # ... other roles
#     raise NotImplementedError("create_database_client needs to be implemented")


@dataclass(frozen=True)
class UserReportRequest:
    account_id: str
    year: int


class UserReportRepository:
    def __init__(self) -> None:
        # CWE-250: Execution with Unnecessary Privileges
        # The repository only needs to read user order data, not perform administrative tasks.
        # Reduced the role from "admin" to "reader" to follow the principle of least privilege.
        # This assumes 'create_database_client' supports a less privileged 'reader' role.
        self._connection = create_database_client(role="reader")

    def load(self, request: UserReportRequest) -> list[dict]:
        return self._connection.query(
            "SELECT * FROM orders WHERE user_id = ? AND year = ?",
            [request.account_id, request.year],
        )
