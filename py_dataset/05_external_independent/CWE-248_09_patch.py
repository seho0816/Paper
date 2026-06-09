class InventoryService:
    def UpdateStock(
        self,
        request,
        context,
    ):
        try:
            quantity = int(
                request.quantity_text
            )
        except ValueError:
            # CWE-248: Uncaught Exception - Handle cases where quantity_text is not a valid integer.
            # Returning a dictionary with an error message is consistent with the service's success return.
            return {
                "updated": False,
                "error": "Invalid quantity format. Quantity must be an integer.",
            }

        # Assuming update_stock is defined elsewhere in the codebase.
        update_stock(
            request.sku,
            quantity,
        )

        return {
            "updated": True,
        }
