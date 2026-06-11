import xml.sax.saxutils

def build_feature_xml(
    feature_names: list[str],
) -> str:
    items = "".join(
        f"<feature>{xml.sax.saxutils.escape(name)}</feature>"
        for name in feature_names
    )

    return (
        "<features>"
        + items
        + "</features>"
    )
