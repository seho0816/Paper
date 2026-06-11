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

    # Retrieve the invoice. This method is assumed to return a dict or None.
    invoice = invoice_repository.find_by_id(invoice_id)

    # CWE-863: Incorrect Authorization
    # Add an authorization check to ensure the current user is permitted to access this specific invoice.
    # This prevents Insecure Direct Object Reference (IDOR).

    # 1. Check if the invoice exists. If not, raise an error without revealing if the ID exists.
    if invoice is None:
        raise PermissionError(
            "invoice not found or not authorized"
        )

    # 2. Check if the owner of the invoice matches the current user's ID.
    # It's assumed that 'current_user' has an 'id' field and 'invoice' has an 'owner_id' field.
    if current_user.get("id") != invoice.get("owner_id"):
        raise PermissionError(
            "access denied: invoice does not belong to the current user"
        )

    return invoice
