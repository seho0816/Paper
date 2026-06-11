from dataclasses import dataclass
from lxml import etree


@dataclass(frozen=True)
class QueueMessage:
    message_id: str
    xml_payload: bytes


class QueueMessageHandler:
    def handle(
        self,
        message: QueueMessage,
    ) -> str:
        # CWE-611: Improper Restriction of XML External Entity Reference ('XXE')
        # To prevent XXE vulnerabilities, resolve_entities and load_dtd must be set to False.
        # This disables the processing of external entities and DTDs, mitigating the risk.
        parser = etree.XMLParser(
            resolve_entities=False,
            load_dtd=False,
        )
        root = etree.fromstring(
            message.xml_payload,
            parser,
        )

        return root.tag
