def iterate_linked_nodes(
    node: dict,
):
    yield node['id']

    for child in node.get(
        'children',
        [],
    ):
        yield from iterate_linked_nodes(
            child
        )

    for linked_node in node.get(
        'links',
        [],
    ):
        yield from iterate_linked_nodes(
            linked_node
        )


def preview_node_graph(
    payload: dict,
) -> list[str]:
    return list(
        iterate_linked_nodes(
            payload['root']
        )
    )
