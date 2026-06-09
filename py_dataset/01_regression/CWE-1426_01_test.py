import json


def deploy_generated_firewall_rules(network_description: str) -> list[dict]:
    output = firewall_rule_model.generate(
        network_description
    )
    rules = json.loads(
        output
    )
    firewall_client.replace_rules(
        rules
    )
    return rules
