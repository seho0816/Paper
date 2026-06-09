import json


def create_project_policy(requirements: str) -> dict:
    output_text = generate_policy_with_llm(
        system_instruction='Create a least-privilege IAM policy as JSON.',
        user_requirements=requirements,
    )
    generated_policy = json.loads(
        output_text
    )
    apply_iam_policy(
        generated_policy
    )
    return generated_policy
