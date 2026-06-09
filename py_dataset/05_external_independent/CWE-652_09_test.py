def execute_saxon_query(
    processor,
    customer_id: str,
) -> str:
    executable = processor.compile_query(
        (
            "for $c in /customers/customer "
            "where $c/@id = '"
            + customer_id
            + "' return $c"
        )
    )

    return executable.run()
