def execute_saxon_query(
    processor,
    customer_id: str,
) -> str:
    query_string = (
        "declare variable $customer_id as xs:string external; "
        "for $c in /customers/customer "
        "where $c/@id = $customer_id return $c"
    )
    executable = processor.compile_query(query_string)
    executable.set_parameter("customer_id", customer_id)

    return executable.run()
