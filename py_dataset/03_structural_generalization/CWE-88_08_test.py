import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class BranchRequest:
    branch_name: str


class GitRepositoryService:
    def checkout(
        self,
        request: BranchRequest,
    ) -> None:
        subprocess.run(
            [
                "git",
                "checkout",
                request.branch_name,
            ],
            check=True,
        )
