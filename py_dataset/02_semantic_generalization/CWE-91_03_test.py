def build_soap_request(
    customer_id: str,
    message: str,
) -> str:
    return (
        "<soap:Envelope>"
        "<soap:Body>"
        "<SendMessage>"
        f"<Customer>{customer_id}</Customer>"
        f"<Message>{message}</Message>"
        "</SendMessage>"
        "</soap:Body>"
        "</soap:Envelope>"
    )
