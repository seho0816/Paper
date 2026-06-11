from dataclasses import dataclass

from lxml import etree


@dataclass(frozen=True)
class XmlImport:
    payload: bytes
    filename: str


class XmlReader:
    def read(
        self,
        request: XmlImport,
    ):
        # CWE-776: Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion)
        # The 'load_dtd=True', 'resolve_entities=True', and 'huge_tree=True' options
        # enable dangerous XML parsing features that can lead to Denial of Service (DoS)
        # through XML Entity Expansion (e.g., Billion Laughs attack) or external entity attacks.
        # By removing these explicit settings, we revert to lxml's secure defaults,
        # which disable DTD loading, entity resolution, and huge tree parsing,
        # thereby mitigating CWE-776.
        parser = etree.XMLParser()

        return etree.fromstring(
            request.payload,
            parser,
        )


class ImportService:
    def __init__(
        self,
        reader: XmlReader,
    ) -> None:
        self._reader = reader

    def import_file(
        self,
        request: XmlImport,
    ) -> str:
        root = self._reader.read(
            request,
        )

        return root.tag
