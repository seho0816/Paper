def find_customer(
    session,
    customer_name: str,
) -> str:
    query = f"""
    for $customer in collection("customers")/customer
    where $customer/name = "{customer_name}"
    return $customer
    """

    return session.execute(
        query
    )
