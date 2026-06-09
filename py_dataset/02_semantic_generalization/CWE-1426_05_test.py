import json


def deploy_gateway_policy(service_description: str) -> dict:
    output = model_client.generate_gateway_policy(
        service_description
    )
    policy = json.loads(output)
    api_gateway.replace_authorization_policy(
        policy
    )
    return policy
