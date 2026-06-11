def find_customer(
    session,
    customer_name: str,
) -> str:
    query = """
    declare variable $customerName external;
    for $customer in collection("customers")/customer
    where $customer/name = $customerName
    return $customer
    """

    return session.execute(
        query,
        {'customerName': customer_name}
    )
