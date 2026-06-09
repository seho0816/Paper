from dataclasses import dataclass


@dataclass(frozen=True)
class BinaryFrame:
    data: bytes


class FrameDecoder:
    def decode(
        self,
        frame: BinaryFrame,
    ) -> tuple[bytes, bytes]:
        metadata_length = int.from_bytes(
            frame.data[:2],
            "big",
        )
        metadata = frame.data[
            2:2 + metadata_length
        ]
        payload = frame.data[
            2 + metadata_length:
        ]

        return metadata, payload
