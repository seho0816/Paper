from dataclasses import dataclass


@dataclass(frozen=True)
class UploadEnvelope:
    packet: bytes


class UploadProtocolParser:
    def parse(
        self,
        envelope: UploadEnvelope,
    ) -> dict:
        # CWE-130: Improper Handling of Unusual or Exceptional Conditions (Buffer Over-read)
        # Validate that the packet is long enough to extract the header length and header/body.
        # The packet must have at least 1 byte to read header_length.
        if len(envelope.packet) < 1:
            return {
                "header": b"",
                "body": b"",
            }

        header_length = envelope.packet[0]

        # The declared header_length must not cause an access beyond the packet's bounds.
        # The header starts at index 1 and extends for header_length bytes.
        # So, it requires 1 (for header_length byte) + header_length bytes in total.
        if 1 + header_length > len(envelope.packet):
            return {
                "header": b"",
                "body": b"",
            }

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
