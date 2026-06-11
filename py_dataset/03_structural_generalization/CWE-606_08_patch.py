class RecordReplicator:
    MAX_REPLICATION_COUNT = 1000

    def stream(self, source_record: dict, requested_count: int):
        # Limit the requested_count to prevent excessive iterations.
        # This mitigates CWE-606 by ensuring the loop condition is based on a checked input,
        # preventing potential Denial of Service from an overly large requested_count.
        # It also handles negative inputs by clamping them to 0.
        effective_count = max(0, min(requested_count, self.MAX_REPLICATION_COUNT))

        current = 0
        while current < effective_count:
            yield {
                **source_record,
                'copy_number': current,
            }
            current += 1
