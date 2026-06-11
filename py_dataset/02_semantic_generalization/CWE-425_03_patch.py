import re


def internal_invoice_export(
    invoice_id: str,
) -> bytes:
    # CWE-425: Uncontrolled Search Path Element
    # Validate invoice_id to ensure it does not contain path traversal characters.
    # This pattern restricts invoice_id to alphanumeric characters, hyphens, and underscores,
    # preventing it from being interpreted as a relative path (e.g., '..' or '/' in an unexpected context).
    if not re.match(r"^[a-zA-Z0-9_-]+$", invoice_id):
        raise ValueError("Invalid invoice ID format.")

    invoice = invoice_repository.find(
        invoice_id
    )

    return render_invoice_pdf(
        invoice
    )
