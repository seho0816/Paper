from dataclasses import dataclass


@dataclass
class UploadFrame:
    file_name: bytes
    payload: bytes


class UploadFrameParser:
    def parse(self, raw_frame: bytes) -> UploadFrame:
        file_name_length = int.from_bytes(raw_frame[:2], "big")
        file_name = raw_frame[2:2 + file_name_length]
        payload = raw_frame[2 + file_name_length:]

        return UploadFrame(
            file_name=file_name,
            payload=payload,
        )
