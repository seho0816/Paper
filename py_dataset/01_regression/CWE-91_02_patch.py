import html

def build_order_xml(
    order_id: str,
    note: str,
) -> str:
    # Escape order_id for use as an XML attribute value.
    # The 'quote=True' argument ensures that single and double quotes are also escaped,
    # which is crucial for attribute values to prevent breaking the XML structure
    # if the attribute's delimiter (here, single quote) appears in the value.
    # It escapes '&', '<', '>', '"', and '''.
    escaped_order_id = html.escape(order_id, quote=True)

    # Escape note for use as XML element content.
    # The default behavior of html.escape (quote=False) is suitable for element content,
    # escaping '&', '<', and '>'.
    escaped_note = html.escape(note)

    return (
        "<order id='{0}'>"
        "<note>{1}</note>"
        "</order>"
    ).format(
        escaped_order_id,
        escaped_note,
    )
