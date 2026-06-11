from flask import request
from lxml import etree


def parse_xml():
    parser = etree.XMLParser(
        resolve_entities=False,  # CWE-611 fix: Disable resolution of external entities
        load_dtd=False,          # CWE-611 fix: Disable DTD loading
    )
    root = etree.fromstring(
        request.data,
        parser,
    )

    return root.tag
