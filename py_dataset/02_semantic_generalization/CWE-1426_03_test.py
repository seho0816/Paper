import json


def configure_bucket_policy(requirements: str) -> dict:
    policy_text = policy_generator.create_bucket_policy(
        requirements
    )
    policy = json.loads(
        policy_text
    )
    object_storage.set_bucket_policy(
        'project-assets',
        policy,
    )
    return policy
