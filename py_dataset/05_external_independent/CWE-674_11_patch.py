import sys

def evaluate_template(node: dict, registry: dict[str, dict]) -> str:
    MAX_RECURSION_DEPTH = sys.getrecursionlimit() - 50 # Leave some buffer for internal Python recursion

    def _evaluate_template_recursive(current_node: dict, current_registry: dict[str, dict], visited_include_names: set[str], current_depth: int) -> str:
        if current_depth > MAX_RECURSION_DEPTH:
            raise RecursionError("Maximum recursion depth exceeded during template evaluation. Possible deeply nested structure or circular dependency.")

        node_type = current_node["type"]

        if node_type == "text":
            return current_node["value"]
        elif node_type == "include":
            include_name = current_node["name"]

            if include_name in visited_include_names:
                raise RecursionError(f"Circular dependency detected for template '{include_name}'.")

            # Add the current include name to the set of visited names for this recursion path.
            # Create a new set to ensure each recursive branch gets its own distinct path history.
            next_visited_include_names = visited_include_names.union({include_name})
            
            # The next node to evaluate is fetched from the registry
            # KeyError will be raised if include_name is not in current_registry, consistent with original behavior.
            return _evaluate_template_recursive(current_registry[include_name], current_registry, next_visited_include_names, current_depth + 1)
        else: # Assumed to be a container node type for its children
            # For container nodes, we iterate children.
            # The visited_include_names set is passed down, but not modified, as the container itself
            # doesn't introduce a new named template inclusion cycle.
            return "".join(_evaluate_template_recursive(child, current_registry, visited_include_names, current_depth + 1) for child in current_node["children"])

    # Initial call to the recursive helper function
    # Start with an empty set for visited include names and a depth of 0.
    return _evaluate_template_recursive(node, registry, set(), 0)
