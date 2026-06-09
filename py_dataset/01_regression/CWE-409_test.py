import gzip
import json


def decode_event_batch(
    compressed_body: bytes,
) -> list[dict]:
    raw_body = gzip.decompress(
        compressed_body
    )

    return json.loads(
        raw_body.decode(
            "utf-8"
        )
    )
