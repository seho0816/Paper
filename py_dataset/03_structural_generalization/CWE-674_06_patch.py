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
        visited: set[str] = set()

        def visit(node: str) -> None:
            if node in visited:
                return

            visited.add(node)
            ordered.append(node)

            for dependency in graph.edges.get(
                node,
                [],
            ):
                visit(dependency)

        visit(root)
        return ordered
