class AuditFileReader:
    def read_window(self, audit_path: str, request_query: dict[str, int]) -> bytes:
        offset = request_query["offset"]
        length = request_query["length"]

        with open(audit_path, "rb") as audit_file:
            audit_file.seek(offset)
            return audit_file.read(length)
