from xml.dom import minidom


def read_invoice_xml(
    xml_text: str,
) -> str:
    document = minidom.parseString(
        xml_text,
    )

    return document.documentElement.tagName
