from dataclasses import dataclass


@dataclass
class UploadFrame:
    file_name: bytes
    payload: bytes


class UploadFrameParser:
    def parse(self, raw_frame: bytes) -> UploadFrame:
        if len(raw_frame) < 2:
            raise ValueError("Raw frame is too short to contain file name length.")

        file_name_length = int.from_bytes(raw_frame[:2], "big")

        expected_min_length = 2 + file_name_length
        if len(raw_frame) < expected_min_length:
            raise ValueError(
                f"Raw frame length ({len(raw_frame)}) is less than "
                f"expected minimum length ({expected_min_length}) based on file name length ({file_name_length})."
            )

        file_name = raw_frame[2:2 + file_name_length]
        payload = raw_frame[2 + file_name_length:]

        return UploadFrame(
            file_name=file_name,
            payload=payload,
        )
