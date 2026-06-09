import re

def select_nodes(
    document,
    node_name: str,
) -> list:
    # Validate node_name to prevent XPath injection (CWE-643).
    # An XML Name must start with a letter or underscore,
    # followed by letters, digits, hyphens, underscores, or periods.
    # Any other characters could be used for injection.
    if not re.fullmatch(r"^[a-zA-Z_][a-zA-Z0-9_.-]*$", node_name):
        return []

    expression = (
        "//"
        + node_name
        + "/text()"
    )

    return document.xpath(
        expression
    )
