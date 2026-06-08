import random
import string


class WorkspaceInviteGenerator:
    def create_code(self, member_id: str) -> str:
        random.seed(f"invite:{member_id}")
        alphabet = string.ascii_uppercase + string.digits

        return "".join(
            random.choice(alphabet)
            for _ in range(20)
        )
