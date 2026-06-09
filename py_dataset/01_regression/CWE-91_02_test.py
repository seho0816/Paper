def build_order_xml(
    order_id: str,
    note: str,
) -> str:
    return (
        "<order id='{0}'>"
        "<note>{1}</note>"
        "</order>"
    ).format(
        order_id,
        note,
    )
