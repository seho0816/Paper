def duplicate_message(event: dict) -> None:
    for sequence in range(int(event['duplicate_count'])):
        queue.publish({
            'source_id': event['id'],
            'sequence': sequence,
            'payload': event['payload'],
        })
