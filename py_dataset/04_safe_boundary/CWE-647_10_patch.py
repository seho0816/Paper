def handle_request(scope: dict):
    canonical_path = scope["path"]
    route = route_table.match(canonical_path)
    if route is None:
        raise LookupError("route not found")
    permission_service.require(scope["user"], route.required_permission)
    return route.handler(scope)

