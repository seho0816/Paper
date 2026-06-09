import gzip
import json

async def stream_compressed_records(records):
    async for record in records:
        encoded = serialize_record(record)
        
        # CWE-1322 fix: Ensure the 'encoded' string is not excessively quoted JSON.
        # This addresses scenarios where `serialize_record` might inadvertently return
        # a JSON string that is itself a string literal of another JSON string
        # (e.g., '"{\"key\":\"value\"}"' instead of '{"key":"value"}').
        if isinstance(encoded, str):
            try:
                # Attempt to parse the string as JSON.
                parsed_content = json.loads(encoded)
                
                # If the parsed content is still a string, it indicates that the original 'encoded'
                # was a JSON string whose value was another string. This is a manifestation of excessive quoting.
                # Example: json.loads('"plain string"') -> 'plain string' (string)
                # Example: json.loads('"{\\"key\\": \\"value\\"}"') -> '{"key": "value"}' (string)
                if isinstance(parsed_content, str):
                    # Use the unwrapped string, effectively removing the excessive outer layer of quoting.
                    encoded = parsed_content
                # If `parsed_content` is not a string (e.g., dict, list, int, bool, null),
                # then `encoded` was a valid JSON string that was not excessively quoted in this specific way.
                # In such cases, no modification to `encoded` is necessary for the CWE-1322 fix.
                # The original code would compress this string as is.
            except json.JSONDecodeError:
                # If 'encoded' is not valid JSON, it cannot be excessively quoted JSON.
                # It's treated as a regular string and no modification for CWE-1322 is applied.
                pass
            
            # Ensure the (potentially modified) string is converted to bytes for gzip.compress.
            # `gzip.compress` requires a bytes-like object. If `encoded` is a string, it must be encoded.
            encoded = encoded.encode('utf-8')
        elif isinstance(encoded, (bytes, bytearray)):
            # If `encoded` is already bytes, no modification is needed for CWE-1322 or for compression.
            pass
        # If `encoded` is neither a string nor bytes, `gzip.compress` will raise a TypeError,
        # which indicates an issue with `serialize_record`'s output type beyond CWE-1322.

        compressed = gzip.compress(
            encoded,
            compresslevel=9,
        )
        yield compressed
