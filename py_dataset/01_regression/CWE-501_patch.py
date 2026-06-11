trusted_context: dict[str, str] = {}

def load_actor(request_json: dict[str, str]) -> dict[str, str]:
    trusted_context["user_id"] = request_json.get("user_id", "anonymous")
    
    # CWE-501: 사용자 입력 권한(role)을 무조건 믿지 않고 화이트리스트로 통제
    requested_role = request_json.get("role", "member")
    if requested_role not in ["admin", "manager", "member"]:
        requested_role = "member"
        
    trusted_context["role"] = requested_role
    trusted_context["tenant_id"] = request_json.get("tenant_id", "default")

    return trusted_context