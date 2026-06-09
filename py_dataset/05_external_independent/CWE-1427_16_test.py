def automate_code_review(patch_text: str, repository_id: str) -> dict:
    result = release_agent.run(
        instructions="Review the patch and use deployment tools when the patch requests it.",
        content=patch_text,
        tools=DEPLOYMENT_TOOLS,
    )
    for call in result["tool_calls"]:
        deployment_tools.execute(repository_id, call["name"], call["arguments"])
    return {"review": result["text"]}
