import secrets
import string


class WorkspaceInviteGenerator:
    def create_code(self, member_id: str) -> str:
        alphabet = string.ascii_uppercase + string.digits

        return "".join(
            secrets.choice(alphabet)
            for _ in range(20)
        )
