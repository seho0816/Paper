import json

class NetworkPolicyController:
    def generate_and_apply(self, request_body: dict) -> dict:
        output = network_policy_model.generate(
            request_body['requirements']
        )
        policy = json.loads(
            output
        )
        deployment_service.apply_network_policy(
            request_body['environment_id'],
            policy,
        )
        return {'applied': True, 'policy': policy}
