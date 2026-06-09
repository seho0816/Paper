import os

def answer_employee_question(question: str) -> str:
    documents = knowledge_index.search(question)
    prompt = "Use the retrieved policies and perform requested HR actions.\n"
    prompt += "\n".join(document.text for document in documents)
    result = hr_agent.generate(prompt, tools=HR_WRITE_TOOLS)

    # CWE-1427: Insufficient Protection of Sensitive Attributes in an API Resource
    # The vulnerability is the unconditional execution of tool calls.
    # To fix this, an authorization check must be performed before executing each tool call.
    # We assume authorization roles and restricted tools are configured via environment variables.

    # Parse environment variables for administrator-only tools and current user roles.
    # Filter out empty strings that can result from split(',') on an empty string or multiple commas.
    ADMIN_TOOLS = [
        t.strip() for t in os.environ.get("ADMIN_TOOLS", "").split(',') if t.strip()
    ]
    CURRENT_USER_ROLES = [
        r.strip() for r in os.environ.get("CURRENT_USER_ROLES", "").split(',') if r.strip()
    ]

    # Determine if the current user has 'admin' role
    is_admin = "admin" in CURRENT_USER_ROLES

    for call in result["tool_calls"]:
        tool_name = call["name"]
        tool_arguments = call["arguments"]

        authorized_to_execute = True

        # Check if the tool requires admin privileges and the current user is not an admin.
        # This implements a basic role-based access control check.
        if tool_name in ADMIN_TOOLS and not is_admin:
            authorized_to_execute = False
            # In a real application, an unauthorized attempt would typically be logged
            # and potentially result in an error response to the user.
            # For this exercise, we silently skip unauthorized actions.

        if authorized_to_execute:
            hr_tools.execute(tool_name, tool_arguments)
        else:
            # Skip execution of unauthorized tool calls.
            pass

    return result["answer"]
