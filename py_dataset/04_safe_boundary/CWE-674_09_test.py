MAX_NESTING = 64

def flatten_json(value) -> list[object]:
    output: list[object] = []
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_NESTING:
            raise ValueError("payload too deeply nested")
        if isinstance(node, dict):
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node)
        else:
            output.append(node)
    return output
