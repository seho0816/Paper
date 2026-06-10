class InternalRouteDispatcher:
    def dispatch(self, path: str, current_user: dict) -> dict:
        if path == "/hidden/exports/all-customers":
            return generate_customer_export()

        return {
            "status": "not_found",
        }


def generate_customer_export() -> dict:
    return {
        "download_url": "/downloads/all-customers.csv",
    }
