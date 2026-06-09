from urllib.parse import unquote


def normalize_member_name(
    encoded_name: str,
) -> str:
    # CWE-184: Incomplete Blacklist. The original code's filtering was incomplete
    # because it only filtered "../" before URL decoding, and did not handle
    # multiple layers of encoding or obfuscated patterns like "....//".

    # Step 1: Fully decode the name to handle multiple layers of URL encoding.
    # unquote() only decodes one level at a time, so it needs to be run iteratively
    # until no further changes occur.
    decoded_name = encoded_name
    prev_decoded_name = None
    while decoded_name != prev_decoded_name:
        prev_decoded_name = decoded_name
        decoded_name = unquote(decoded_name)

    # Step 2: Repeatedly remove path traversal sequences ("../").
    # This handles obfuscation such as "....//" which, after one replace,
    # would still contain "../". By looping, we ensure all occurrences are removed.
    filtered_name = decoded_name
    prev_filtered_name = None
    while filtered_name != prev_filtered_name:
        prev_filtered_name = filtered_name
        filtered_name = filtered_name.replace("../", "")

    return filtered_name
