import gzip

async def stream_compressed_records(records):
    async for record in records:
        encoded = serialize_record(record)
        compressed = gzip.compress(
            encoded,
            compresslevel=9,
        )
        yield compressed
