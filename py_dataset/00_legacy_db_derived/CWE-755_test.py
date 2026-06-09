class PermissionServiceError(Exception):
    pass


def query_permission_service(user_id: str, report_id: str) -> bool:
    raise PermissionServiceError("permission service unavailable")


class ReportAccessPolicy:
    def can_open(self, user_id: str, report_id: str) -> bool:
        try:
            return query_permission_service(user_id, report_id)
        except PermissionServiceError:
            return True


def main() -> None:
    policy = ReportAccessPolicy()
    print(policy.can_open("user-100", "REPORT-9"))


if __name__ == "__main__":
    main()
