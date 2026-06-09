from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient

# In a real application, the MongoDB client and collection would be configured
# appropriately, potentially using dependency injection or environment variables.
# This is a minimal setup to make the provided code syntactically complete.
client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client["test_db"]
mongo_collection = db["test_collection"]


app = FastAPI()

# Define a set of MongoDB operators that are considered dangerous
# for direct user input, as they can lead to code execution or command injection.
BLOCKED_MONGO_OPERATORS = {
    '$where',      # Allows execution of arbitrary JavaScript code
    '$eval',       # Deprecated, but still dangerous for JavaScript execution
    '$accumulator', # Aggregation operator; generally not applicable to find(), but dangerous
    '$function',   # Aggregation operator; generally not applicable to find(), but dangerous
    '$cmd',        # Allows running arbitrary database commands
    # Other operators like $regex, $text, $mod are generally allowed for filtering
    # but their values (e.g., regex patterns) might need separate validation
    # to prevent ReDoS, which is out of scope for this specific CWE-943 fix.
}

def sanitize_mongo_find_query(query_data: dict) -> dict:
    """
    Recursively sanitizes a MongoDB query dictionary to prevent NoSQL injection.
    It removes or ignores keys that match known dangerous MongoDB operators.
    """
    sanitized_data = {}
    if not isinstance(query_data, dict):
        # If a non-dictionary value is encountered where a dictionary is expected
        # (e.g., during recursive processing), return it as is or handle as an error.
        # For top-level `query`, FastAPI's type hint `query: dict` ensures it's a dict.
        return query_data

    for key, value in query_data.items():
        if key in BLOCKED_MONGO_OPERATORS:
            # If the key is a blocked operator, skip it and its value
            continue

        if isinstance(value, dict):
            # Recursively sanitize nested dictionaries
            sanitized_value = sanitize_mongo_find_query(value)
            if sanitized_value:
                sanitized_data[key] = sanitized_value
        elif isinstance(value, list):
            # Recursively sanitize lists if they contain dictionaries
            sanitized_list = []
            for item in value:
                if isinstance(item, dict):
                    sanitized_item = sanitize_mongo_find_query(item)
                    if sanitized_item:
                        sanitized_list.append(sanitized_item)
                else:
                    sanitized_list.append(item)
            if sanitized_list:
                sanitized_data[key] = sanitized_list
        else:
            # For non-dictionary, non-list values, or allowed operators, keep them as is
            sanitized_data[key] = value
            
    return sanitized_data


@app.post("/api/search")
async def search(
    query: dict,
) -> list[dict]:
    # Sanitize the user-provided query dictionary to remove any dangerous operators
    # before passing it to the MongoDB find method.
    sanitized_query = sanitize_mongo_find_query(query)
    
    # If the sanitized query is empty after removing all potentially malicious parts,
    # or if the original query was empty, return an empty list to prevent
    # `mongo_collection.find({})` which would return all documents.
    if not sanitized_query:
        return []

    cursor = mongo_collection.find(
        sanitized_query
    )

    return [
        document
        async for document in cursor
    ]
