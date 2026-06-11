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

        # CWE-369 fix: Prevent division by zero if item_count is 0
        if request.item_count == 0:
            average_value = 0
        else:
            average_value = total_size / request.item_count

        return {
            "average": average_value,
        }
