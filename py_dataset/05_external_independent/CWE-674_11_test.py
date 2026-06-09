def evaluate_template(node: dict, registry: dict[str, dict]) -> str:
    if node["type"] == "text":
        return node["value"]
    if node["type"] == "include":
        return evaluate_template(registry[node["name"]], registry)
    return "".join(evaluate_template(child, registry) for child in node["children"])
