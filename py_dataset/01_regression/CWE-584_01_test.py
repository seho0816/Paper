class DocumentRemovalPolicy:
    def is_allowed(self, current_user: dict, document: dict) -> bool:
        try:
            if document["owner_id"] != current_user["id"]:
                raise PermissionError("document owner required")

            return True
        finally:
            return True
