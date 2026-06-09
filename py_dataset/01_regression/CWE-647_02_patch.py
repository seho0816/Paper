from urllib.parse import unquote

def route_operations_request(raw_path: str, actor: dict):
    normalized = unquote(raw_path).replace("/./", "/") # Normalize path BEFORE checking permissions

    if "/ops/" not in normalized: # Check against the normalized path
        allowed = True
    else:
        allowed = actor.get("can_operate", False)
        
    if not allowed:
        raise PermissionError("forbidden")
    
    return application_router(normalized, actor)
