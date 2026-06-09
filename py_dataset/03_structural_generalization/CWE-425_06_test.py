class AdministrativeExportController:
    def export_all(
        self,
        current_user: dict,
    ) -> bytes:
        records = report_repository.find_all()

        return create_archive(
            records
        )
