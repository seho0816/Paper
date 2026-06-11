import json
import re


def create_project_policy(requirements: str) -> dict:
    sensitive_patterns = [
        # AWS Access Key IDs, Secret Access Keys (prefixed like AKIA, ASIA)
        r'\b(AKIA|ASIA|AGIA|AROA|AIDA|AFYA)[0-9A-Z]{16}\b',
        # OpenAI style secret keys (sk-...)
        r'\bsk-[a-zA-Z0-9-]{32,64}\b',
        # Generic UUID/hex-like strings that could be API keys/tokens
        r'\b[a-f0-9]{32,64}\b',
        # Private Keys (e.g., RSA, EC)
        r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
        # Common credential assignment patterns (e.g., password=, secret=, api_key=)
        r'\b(password|secret|passwd|api_key|api-key|access_key|access-key|token|auth_token)\s*[=:]\s*["\']?[a-zA-Z0-9!@#$%^&*()_+=\-{}[\]|\\:;<,>.?/`~]{8,128}[\"\']?\b',
        # Bearer tokens in Authorization headers
        r'\bAuthorization:\s*Bearer\s+[a-zA-Z0-9._-]{20,200}\b',
    ]

    scrubbed_requirements = requirements
    for pattern in sensitive_patterns:
        scrubbed_requirements = re.sub(pattern, '[REDACTED_SENSITIVE_DATA]', scrubbed_requirements, flags=re.IGNORECASE | re.DOTALL)

    output_text = generate_policy_with_llm(
        system_instruction='Create a least-privilege IAM policy as JSON.',
        user_requirements=scrubbed_requirements,
    )
    generated_policy = json.loads(
        output_text
    )
    apply_iam_policy(
        generated_policy
    )
    return generated_policy
