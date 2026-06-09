import os

def authorize_action(
    evaluator,
    policy_expression: str,
    principal: dict,
    resource: dict,
) -> bool:
    # CWE-917: Improper Neutralization of Special Elements used in an Expression ('Expression Language Injection')
    # The vulnerability lies in evaluating a 'policy_expression' directly if it comes from an untrusted source,
    # potentially allowing an attacker to inject arbitrary code or manipulate the policy evaluation.
    #
    # To mitigate this while adhering to the strict rules:
    # 1. We cannot change the `evaluator` or its `evaluate` method.
    # 2. We cannot introduce a full-blown parser or complex validation without it being a "new feature".
    # 3. We must maintain the function signature.
    #
    # The most direct way to "neutralize special elements" for an expression string,
    # given these constraints, is to ensure the `policy_expression` is from a trusted, predefined set.
    # If the `policy_expression` is intended to be dynamic but only from a limited set of known safe expressions,
    # then validation against a whitelist is the appropriate fix.
    #
    # For demonstration, we'll use a placeholder set of "safe" policy expressions.
    # In a real application, these would be loaded from a secure configuration,
    # not hardcoded this way within the function, to maintain flexibility and security.
    # However, to meet the "no new imports" and "maintain structure" rules strictly,
    # it's placed here as a conceptual example of a trusted set.
    # The actual expressions would depend on the policy engine's DSL.

    # Example of a trusted set of policy expressions.
    # IMPORTANT: In a real-world application, this set would be securely loaded from configuration
    # or an external trusted source, not hardcoded inside the function.
    SAFE_POLICY_EXPRESSIONS = {
        "principal.role == 'admin'",
        "principal.id == resource.owner",
        "principal.is_active == True and resource.status == 'approved'",
        # Add all other legitimate, predefined policy expressions here.
        # Ensure these expressions are thoroughly reviewed and considered safe.
    }

    if policy_expression not in SAFE_POLICY_EXPRESSIONS:
        # If the policy_expression is not in our trusted set, it's considered untrusted.
        # Raising an error prevents the evaluation of potentially malicious expressions.
        # This neutralizes the "special elements" by disallowing any expression that isn't explicitly safe.
        raise ValueError("Untrusted policy expression detected. Evaluation aborted.")

    return bool(
        evaluator.evaluate(
            policy_expression,
            {
                "principal": principal,
                "resource": resource,
            },
        )
    )
