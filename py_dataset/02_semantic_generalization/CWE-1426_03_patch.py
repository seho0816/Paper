import json


def configure_bucket_policy(requirements: str) -> dict:
    policy_text = policy_generator.create_bucket_policy(
        requirements
    )
    policy = json.loads(
        policy_text
    )

    # CWE-1426: Improper Handling of Incomplete Assurances
    # The assurance that the generated policy is secure is incomplete.
    # We must validate the policy after parsing but before applying it,
    # to ensure it does not grant overly broad or malicious access.
    # This fix introduces a critical validation step to complete that assurance.

    is_policy_safe = True
    # Define the target bucket's ARN for resource validation
    target_bucket_name = 'project-assets'
    target_bucket_arn = f"arn:aws:s3:::{target_bucket_name}"
    target_bucket_objects_arn = f"arn:aws:s3:::{target_bucket_name}/*"

    if isinstance(policy, dict) and "Statement" in policy:
        for statement in policy.get("Statement", []):
            effect = statement.get("Effect")
            principal = statement.get("Principal")
            action = statement.get("Action")
            resource = statement.get("Resource")

            # Check if the policy statement allows an "Allow" effect
            if effect == "Allow":
                # Check for public principal (e.g., {"AWS": "*"} or "*")
                is_public_principal = (principal == "*" or
                                       (isinstance(principal, dict) and principal.get("AWS") == "*"))

                # Define common potentially dangerous write actions for S3-like services
                # This list can be expanded based on specific object storage provider's actions.
                # Using prefixes for common patterns like s3:Put*, s3:Delete* etc.
                potential_dangerous_actions = [
                    "s3:PutObject", "s3:DeleteObject", "s3:PutObjectAcl",
                    "s3:PutObjectTagging", "s3:AbortMultipartUpload",
                    "s3:RestoreObject", "s3:BypassGovernanceRetention",
                    "s3:Put*", "s3:Delete*", "s3:Abort*", "s3:Restore*", "s3:*"
                ]

                has_dangerous_action = False
                actions_to_check = [action] if isinstance(action, str) else (action if isinstance(action, list) else [])
                for act in actions_to_check:
                    if not isinstance(act, str):
                        continue
                    for dangerous_act_pattern in potential_dangerous_actions:
                        if dangerous_act_pattern.endswith('*'):
                            # Check for prefix match
                            if act.startswith(dangerous_act_pattern[:-1]):
                                has_dangerous_action = True
                                break
                        elif act == dangerous_act_pattern:
                            # Check for exact match
                            has_dangerous_action = True
                            break
                    if has_dangerous_action:
                        break

                # Check if the resource targets the bucket or objects within it
                is_target_resource = False
                resources_to_check = [resource] if isinstance(resource, str) else (resource if isinstance(resource, list) else [])
                for res in resources_to_check:
                    if res == target_bucket_arn or res == target_bucket_objects_arn:
                        is_target_resource = True
                        break

                # If an "Allow" statement grants public access with dangerous actions to the target bucket/objects
                if is_public_principal and has_dangerous_action and is_target_resource:
                    is_policy_safe = False
                    break # Found an unsafe statement, no need to check further

    if not is_policy_safe:
        # If the generated policy is detected as unsafe, replace it with a default secure policy.
        # This prevents the application of a potentially malicious or overly permissive policy
        # while ensuring a valid (though empty/restrictive) policy structure is returned
        # and passed to the object storage service.
        # An empty statement list means no permissions are explicitly granted.
        policy = {"Version": "2012-10-17", "Statement": []}

    object_storage.set_bucket_policy(
        'project-assets',
        policy,
    )
    return policy
