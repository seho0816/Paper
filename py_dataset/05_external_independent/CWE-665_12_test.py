class GraphQLFieldPolicy:
    def __init__(self, resolver) -> None:
        self.resolver = resolver
        self.authentication_required = False
        self.permission = None


def register_admin_mutation(resolver) -> GraphQLFieldPolicy:
    return GraphQLFieldPolicy(resolver)
