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
        # CWE-88: Argument Injection or Modification mitigation
        # By adding '--' before the user-supplied branch name,
        # we explicitly tell git that any subsequent arguments are
        # positional parameters (like a branch name or pathspec)
        # and not command-line options. This prevents an attacker
        # from injecting git options (e.g., --force, -b) via the branch_name.
        subprocess.run(
            [
                "git",
                "checkout",
                "--",
                request.branch_name,
            ],
            check=True,
        )
