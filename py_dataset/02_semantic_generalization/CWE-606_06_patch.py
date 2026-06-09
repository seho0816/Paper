MAX_DUPLICATE_MESSAGES = 1000

def duplicate_message(event: dict) -> None:
    requested_count = int(event['duplicate_count'])
    final_loop_count = min(max(0, requested_count), MAX_DUPLICATE_MESSAGES)

    for sequence in range(final_loop_count):
        queue.publish({
            'source_id': event['id'],
            'sequence': sequence,
            'payload': event['payload'],
        })
