class PermissionServiceError(Exception):
    pass


def query_permission_service(user_id: str, report_id: str) -> bool:
    # In a real application, this would query an actual permission service.
    # For this example, it simulates an unavailable service.
    raise PermissionServiceError("permission service unavailable")


class ReportAccessPolicy:
    def can_open(self, user_id: str, report_id: str) -> bool:
        try:
            return query_permission_service(user_id, report_id)
        except PermissionServiceError:
            # CWE-755 fix:
            # The original code would return True here, meaning if the permission
            # service was unavailable, access would be granted by default (fail-open).
            # This is an improper handling of an exceptional condition from a security
            # perspective. To prevent unauthorized access when the service is down,
            # we should default to denying access (fail-closed).
            return False


def main() -> None:
    policy = ReportAccessPolicy()
    print(policy.can_open("user-100", "REPORT-9"))


if __name__ == "__main__":
    main()
