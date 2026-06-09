class BatchService:
    def AverageSize(
        self,
        request,
        context,
    ):
        total_size = sum(
            item.size
            for item in request.items
        )

        return {
            "average": (
                total_size
                / request.item_count
            ),
        }
