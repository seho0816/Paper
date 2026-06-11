class InternalRouteDispatcher:
    def dispatch(self, path: str, current_user: dict) -> dict:
        if path == "/hidden/exports/all-customers":
            # CWE-425 fix: Ensure proper authorization before allowing access
            # Assuming 'current_user' dictionary contains a 'role' key,
            # and only users with 'admin' role are permitted to access this path.
            if current_user.get("role") == "admin":
                return generate_customer_export()
            else:
                return {
                    "status": "forbidden",
                    "message": "Access denied. Admin privileges required.",
                }

        return {
            "status": "not_found",
        }


def generate_customer_export() -> dict:
    return {
        "download_url": "/downloads/all-customers.csv",
    }
