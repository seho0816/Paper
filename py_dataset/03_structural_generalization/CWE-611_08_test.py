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
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
        )
        root = etree.fromstring(
            message.xml_payload,
            parser,
        )

        return root.tag
