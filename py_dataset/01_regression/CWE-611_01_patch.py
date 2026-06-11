import xml.etree.ElementTree as ET


def read_invoice_xml(
    xml_text: str,
) -> str:
    parser = ET.XMLParser(resolve_entities=False)
    root = ET.fromstring(xml_text, parser=parser)

    return root.tag
