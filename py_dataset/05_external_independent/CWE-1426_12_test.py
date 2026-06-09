import json


def resolve_generate_policy(_root, info, requirements: str) -> dict:
    output = info.context.policy_model.generate(
        requirements
    )
    policy = json.loads(
        output
    )
    info.context.policy_admin.apply(
        policy
    )
    return {'policy': policy, 'applied': True}
