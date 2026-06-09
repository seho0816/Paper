from lxml import etree
import sys
from pathlib import Path


class PartnerXmlReader:
    def parse_bytes(self, xml_body: bytes):
        parser = etree.XMLParser(
            load_dtd=True,
            resolve_entities=True,
            no_network=False,
        )
        return etree.fromstring(xml_body, parser=parser)


def read_xml_body() -> bytes:
    if len(sys.argv) > 1:
        return Path(sys.argv[1]).read_bytes()

    return b"<!DOCTYPE root [<!ENTITY a 'x'>]><root>&a;</root>"


def main() -> None:
    reader = PartnerXmlReader()
    print(reader.parse_bytes(read_xml_body()).tag)


if __name__ == "__main__":
    main()
