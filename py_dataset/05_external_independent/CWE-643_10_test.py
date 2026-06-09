def resolve_xml_search(
    _root,
    _info,
    customer_name: str,
) -> list:
    expression = (
        "//customer[name='"
        + customer_name
        + "']"
    )

    return customer_xml.xpath(
        expression
    )
