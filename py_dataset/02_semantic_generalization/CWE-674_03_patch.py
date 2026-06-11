def render_category_tree(category_id: str, relations: dict[str, list[str]]) -> dict:
    """
    Renders a category tree structure.

    This function has been modified to prevent uncontrolled recursion (CWE-674)
    by detecting cycles in the category relations.

    Args:
        category_id: The ID of the root category to start rendering from.
        relations: A dictionary where keys are category IDs and values are lists
                   of their direct child category IDs.

    Returns:
        A dictionary representing the category tree, with 'id' and 'children' keys.
        If a cycle is detected, the branch causing the cycle will have its 'children'
        list truncated to an empty list to prevent infinite recursion.
    """

    def _render_recursive_safe(current_id: str, rels: dict[str, list[str]], visited_in_path: set[str]) -> dict:
        """
        Helper function to recursively render the tree while tracking visited nodes
        in the current path to detect and prevent cycles.

        Args:
            current_id: The ID of the current category being processed.
            rels: The category relations dictionary.
            visited_in_path: A set of category IDs that are currently in the recursion path.
                             Used to detect cycles.

        Returns:
            A dictionary representing the subtree rooted at current_id.
        """
        if current_id in visited_in_path:
            # Cycle detected: This node has already been encountered in the current
            # recursion path, meaning a loop exists. Terminate this branch to
            # prevent infinite recursion (CWE-674).
            return {"id": current_id, "children": []}

        # Add the current node to the set of visited nodes for the current path.
        # This ensures that subsequent recursive calls down this path can detect if they loop back to current_id.
        visited_in_path.add(current_id)

        children_data = []
        for child_id in rels.get(current_id, []):
            child_tree = _render_recursive_safe(child_id, rels, visited_in_path)
            children_data.append(child_tree)

        # Remove the current node from the set as we backtrack from this recursion level.
        # This allows the same node to be visited again via a different, non-cyclic path
        # from a sibling branch without falsely marking it as a cycle.
        visited_in_path.remove(current_id)

        return {"id": current_id, "children": children_data}

    # Initialize the recursion with an empty set for visited nodes in the path.
    return _render_recursive_safe(category_id, relations, set())
