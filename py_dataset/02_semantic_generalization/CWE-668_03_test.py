import json

def get_contract(workspace_id: str, contract_id: str) -> dict:
    cache_key = f"contract:{contract_id}"
    cached = redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    contract = contract_repository.load(workspace_id, contract_id)
    redis_client.setex(cache_key, 300, json.dumps(contract))
    return contract
