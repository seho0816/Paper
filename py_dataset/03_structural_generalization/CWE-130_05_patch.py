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

        # CWE-130: Improper Handling of Length Parameter Inconsistency
        # This check ensures that the declared metadata_length, when combined with the 2-byte
        # length field itself, does not exceed the total available length of the frame data.
        # If the frame data is shorter than 2 bytes, this check will also correctly
        # identify it as an inconsistency (e.g., if frame.data is b'', metadata_length is 0,
        # but 2 + 0 > 0, raising an error).
        total_expected_data_length = 2 + metadata_length
        if total_expected_data_length > len(frame.data):
            raise ValueError(
                f"Declared metadata length ({metadata_length}) is inconsistent with "
                f"total frame data length ({len(frame.data)}). "
                f"Expected total {total_expected_data_length} bytes, but got {len(frame.data)}."
            )

        metadata = frame.data[
            2:total_expected_data_length
        ]
        payload = frame.data[
            total_expected_data_length:
        ]

        return metadata, payload
