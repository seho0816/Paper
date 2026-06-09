import ipaddress
import json

ALLOWED_PROTOCOLS = {
    'tcp',
    'udp',
}


def validate_firewall_rules(rules: object) -> list[dict]:
    if not isinstance(rules, list) or len(rules) > 20:
        raise ValueError('invalid firewall rule list')

    validated = []
    for rule in rules:
        if rule.get('protocol') not in ALLOWED_PROTOCOLS:
            raise ValueError('unsupported protocol')
        port = rule.get('port')
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('invalid port')
        network = ipaddress.ip_network(
            rule.get('source'),
            strict=True,
        )
        if network.prefixlen < 24:
            raise PermissionError('source network is too broad')
        validated.append(rule)

    return validated


def prepare_firewall_rules(description: str) -> list[dict]:
    generated = firewall_rule_model.generate(
        description
    )
    rules = validate_firewall_rules(
        json.loads(generated)
    )
    firewall_client.stage_rules_for_review(
        rules
    )
    return rules

