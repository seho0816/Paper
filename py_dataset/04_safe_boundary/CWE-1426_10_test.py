import json

ALLOWED_ACTIONS = {
    's3:GetObject',
    's3:ListBucket',
}
ALLOWED_RESOURCE_PREFIX = 'arn:aws:s3:::project-public/'


def validate_generated_policy(policy: dict) -> dict:
    statements = policy.get('Statement')
    if not isinstance(statements, list) or not statements:
        raise ValueError('invalid policy statements')

    for statement in statements:
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if not set(actions).issubset(ALLOWED_ACTIONS):
            raise PermissionError('generated action is not allowed')
        if not resources or not all(
            resource.startswith(ALLOWED_RESOURCE_PREFIX)
            for resource in resources
        ):
            raise PermissionError('generated resource is not allowed')

    return policy


def create_project_policy(requirements: str) -> dict:
    output_text = generate_policy_with_llm(
        system_instruction='Create a least-privilege IAM policy as JSON.',
        user_requirements=requirements,
    )
    policy = validate_generated_policy(
        json.loads(output_text)
    )
    queue_policy_for_human_approval(
        policy
    )
    return policy
