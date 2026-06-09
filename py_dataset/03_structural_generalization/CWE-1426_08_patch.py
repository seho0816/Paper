import json
from dataclasses import dataclass

@dataclass(frozen=True)
class AccessModelRequested:
    resource_id: str
    description: str

class GeneratedAclConsumer:
    async def handle(self, event: AccessModelRequested) -> None:
        output = await access_llm.generate(
            event.description
        )
        try:
            acl = json.loads(
                output
            )
            await acl_repository.replace(
                event.resource_id,
                acl,
            )
        except json.JSONDecodeError as e:
            # CWE-1426: Improper Handling of Syntactically Incorrect Input.
            # The access_llm.generate method might return output that is not valid JSON.
            # The original code would crash with a json.JSONDecodeError if the output is malformed.
            # By wrapping the json.loads call and subsequent operations in a try-except block,
            # we explicitly handle this syntactically incorrect input.
            # Re-raising the exception ensures that the failure to parse the ACL is propagated,
            # preventing the processing of an invalid ACL and maintaining error visibility,
            # without allowing the application to crash unexpectedly.
            raise e
