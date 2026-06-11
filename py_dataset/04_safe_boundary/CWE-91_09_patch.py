from xml.sax.saxutils import escape


def build_message_xml(
    message: str,
) -> str:
    safe_message = escape(
        message,
        entities={
            '"': "&quot;",
            "'": "&apos;",
        },
    )

    return (
        "<message>"
        + safe_message
        + "</message>"
    )

