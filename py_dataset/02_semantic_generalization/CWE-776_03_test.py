import xmltodict


def parse_document(
    xml_text: str,
) -> dict:
    return xmltodict.parse(
        xml_text,
        disable_entities=False,
    )
