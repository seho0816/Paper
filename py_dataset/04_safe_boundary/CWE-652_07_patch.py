QUERY = """
declare variable $customer_name external;

for $customer in collection("customers")/customer
where $customer/name = $customer_name
return $customer
"""


def find_customer(
    session,
    customer_name: str,
) -> str:
    prepared = session.prepare(
        QUERY
    )
    prepared.bind(
        "customer_name",
        customer_name,
    )

    return prepared.execute()

