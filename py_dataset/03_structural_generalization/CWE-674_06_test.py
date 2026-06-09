from dataclasses import dataclass


@dataclass(frozen=True)
class DependencyGraph:
    edges: dict[str, list[str]]


class DependencyWalker:
    def walk(
        self,
        graph: DependencyGraph,
        root: str,
    ) -> list[str]:
        ordered: list[str] = []

        def visit(node: str) -> None:
            ordered.append(node)

            for dependency in graph.edges.get(
                node,
                [],
            ):
                visit(dependency)

        visit(root)
        return ordered
