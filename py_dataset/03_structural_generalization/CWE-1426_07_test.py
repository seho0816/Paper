import json
from dataclasses import dataclass

@dataclass(frozen=True)
class PolicyGenerationRequest:
    requirements: str
    project_id: str

class PolicyGenerationPipeline:
    def execute(self, request: PolicyGenerationRequest) -> dict:
        text = llm_client.generate(
            request.requirements
        )
        policy = json.loads(
            text
        )
        policy_deployer.apply(
            request.project_id,
            policy,
        )
        return policy
