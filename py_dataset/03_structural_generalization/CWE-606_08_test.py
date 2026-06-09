class RecordReplicator:
    def stream(self, source_record: dict, requested_count: int):
        current = 0
        while current < requested_count:
            yield {
                **source_record,
                'copy_number': current,
            }
            current += 1
