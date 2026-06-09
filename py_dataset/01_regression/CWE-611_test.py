from flask import request
from lxml import etree


def parse_xml():
    parser = etree.XMLParser(
        resolve_entities=True,
        load_dtd=True,
    )
    root = etree.fromstring(
        request.data,
        parser,
    )

    return root.tag
