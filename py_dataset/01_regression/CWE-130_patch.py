def parse_upload_packet(
    packet: bytes,
) -> tuple[bytes, bytes]:
    # Ensure the packet is not empty to safely access packet[0]
    if not packet:
        return b'', b''

    name_length_byte = packet[0]
    
    # Calculate the actual end index for the filename,
    # ensuring it does not exceed the packet's bounds.
    # The filename starts at index 1.
    name_start_index = 1
    
    # The declared end index for the filename based on name_length_byte
    declared_name_end_index = name_start_index + name_length_byte
    
    # The actual end index for the filename must be within the packet's length.
    # We take the minimum of the declared end index and the total packet length
    # to prevent reading beyond the buffer.
    actual_name_end_index = min(declared_name_end_index, len(packet))

    # Slice the filename using the safe actual_name_end_index
    file_name = packet[name_start_index:actual_name_end_index]
    
    # The file body starts immediately after the filename
    file_body = packet[actual_name_end_index:]

    return file_name, file_body
