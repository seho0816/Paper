class AdministrativeExportController:
    def export_all(
        self,
        current_user: dict,
    ) -> bytes:
        # CWE-425: Direct Request ('Forced Browsing')
        # Ensure that only authorized users (e.g., administrators) can access this sensitive administrative function.
        # This prevents unauthorized users from directly requesting and accessing administrative exports.
        if not current_user or current_user.get("role") != "admin":
            raise PermissionError("User is not authorized to perform this action.")

        records = report_repository.find_all()

        return create_archive(
            records
        )
