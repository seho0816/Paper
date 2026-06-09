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
        acl = json.loads(
            output
        )
        await acl_repository.replace(
            event.resource_id,
            acl,
        )
