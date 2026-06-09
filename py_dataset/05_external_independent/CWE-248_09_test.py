class InventoryService:
    def UpdateStock(
        self,
        request,
        context,
    ):
        quantity = int(
            request.quantity_text
        )
        update_stock(
            request.sku,
            quantity,
        )

        return {
            "updated": True,
        }
