class MaintenanceService:
    def RebuildIndex(
        self,
        request,
        context,
    ):
        rebuild_search_index(
            request.index_name
        )

        return {
            "completed": True,
        }
