def iterate_linked_nodes(
    node: dict,
):
    visited_nodes = set()
    max_recursion_depth = 1000

    def _recursive_iterator(current_node: dict, current_depth: int):
        if current_depth > max_recursion_depth:
            return

        if 'id' not in current_node:
            return

        node_id = current_node['id']

        if node_id in visited_nodes:
            return

        visited_nodes.add(node_id)
        yield node_id

        next_depth = current_depth + 1

        for child in current_node.get(
            'children',
            [],
        ):
            yield from _recursive_iterator(
                child,
                next_depth,
            )

        for linked_node in current_node.get(
            'links',
            [],
        ):
            yield from _recursive_iterator(
                linked_node,
                next_depth,
            )

    yield from _recursive_iterator(node, 0)


def preview_node_graph(
    payload: dict,
) -> list[str]:
    return list(
        iterate_linked_nodes(
            payload['root']
        )
    )
