class DownloadAuthorizationService:
    def can_download(self, current_user_id: str, file_id: str) -> bool:
        access_policy = find_file_policy(file_id)

        if access_policy is None:
            return False

        if access_policy["public"]:
            return True

        return current_user_id in access_policy["allowed_user_ids"]


def find_file_policy(file_id: str) -> dict | None:
    return None
