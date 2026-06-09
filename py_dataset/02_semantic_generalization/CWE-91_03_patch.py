from xml.sax.saxutils import escape

def build_soap_request(
    customer_id: str,
    message: str,
) -> str:
    # CWE-91: XML Injection - Escape special characters to prevent injection
    escaped_customer_id = escape(customer_id)
    escaped_message = escape(message)
    return (
        "<soap:Envelope>"
        "<soap:Body>"
        "<SendMessage>"
        f"<Customer>{escaped_customer_id}</Customer>"
        f"<Message>{escaped_message}</Message>"
        "</SendMessage>"
        "</soap:Body>"
        "</soap:Envelope>"
    )
