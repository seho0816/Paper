def resolve_xml_search(
    _root,
    _info,
    customer_name: str,
) -> list:
    expression = "//customer[name=$customer_name_var]"

    return customer_xml.xpath(
        expression,
        customer_name_var=customer_name
    )
