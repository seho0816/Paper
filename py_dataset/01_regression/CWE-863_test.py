def download_invoice(
    current_user: dict,
    invoice_id: str,
) -> dict:
    if not current_user.get(
        "authenticated",
    ):
        raise PermissionError(
            "authentication required"
        )

    return invoice_repository.find_by_id(
        invoice_id,
    )
