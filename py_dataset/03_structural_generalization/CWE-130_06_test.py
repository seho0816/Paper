from dataclasses import dataclass


@dataclass(frozen=True)
class UploadEnvelope:
    packet: bytes


class UploadProtocolParser:
    def parse(
        self,
        envelope: UploadEnvelope,
    ) -> dict:
        header_length = envelope.packet[
            0
        ]
        header = envelope.packet[
            1:1 + header_length
        ]
        body = envelope.packet[
            1 + header_length:
        ]

        return {
            "header": header,
            "body": body,
        }
