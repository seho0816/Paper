class AdminExportController:
    def download(self, current_user: dict) -> tuple[int, dict, bytes]:
        if current_user.get("role") != "administrator":
            redirect_response = (
                302,
                {"Location": "/sign-in"},
                b"",
            )

        export_bytes = create_full_customer_export()

        return (
            200,
            {"Content-Type": "text/csv"},
            export_bytes,
        )


def create_full_customer_export() -> bytes:
    return b"user_id,email\n1,owner@example.com"
