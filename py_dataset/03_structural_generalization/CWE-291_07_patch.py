from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    remote_address: str


class PrincipalResolver:
    def resolve(
        self,
        context: RequestContext,
    ) -> dict:
        # CWE-291 (Trust Boundary Violation) exists because the 'administrator' role
        # was granted if `context.remote_address` started with "10.".
        # If `remote_address` could be spoofed by an attacker (e.g., via X-Forwarded-For headers
        # in an improperly configured proxy environment), this would lead to privilege escalation.
        # To fix this, the application must not grant elevated privileges based on potentially
        # untrusted input like `remote_address`. The safest patch is to remove this
        # privilege escalation path.
        return {
            "authenticated": False,
            "role": "anonymous",
        }
