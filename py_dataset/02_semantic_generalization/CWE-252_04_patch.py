def send_secure_record(
    connection,
    record: bytes,
) -> None:
    total_sent_bytes = 0
    record_length = len(record)
    
    # CWE-252 fix: Ensure the return value of connection.send is checked
    # and all bytes are sent before marking the record as delivered.
    while total_sent_bytes < record_length:
        try:
            # connection.send() returns the number of bytes actually sent.
            # This return value must be checked to ensure all data is transmitted.
            sent_this_chunk = connection.send(record[total_sent_bytes:])
            
            if sent_this_chunk == 0:
                # A return value of 0 bytes typically indicates that the
                # connection has been closed by the peer. If this happens
                # while sending, the record cannot be fully delivered.
                raise OSError("Connection closed unexpectedly or send buffer full without progress.")
            
            total_sent_bytes += sent_this_chunk
        except OSError as e:
            # Catch OS-level errors (e.g., connection reset, network unreachable)
            # that connection.send might raise.
            raise RuntimeError(f"Failed to send data completely due to connection error: {e}") from e
        except Exception as e:
            # Catch any other unexpected exceptions during the send operation.
            raise RuntimeError(f"An unexpected error occurred during data send: {e}") from e
            
    # Only call mark_record_delivered() if all bytes of the record
    # were successfully sent over the connection.
    mark_record_delivered()
