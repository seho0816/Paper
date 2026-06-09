def propose_account_actions(actor, external_text: str) -> dict:
    result = llm_client.run(
        system="Return a structured proposal only.",
        user_content=external_text,
        tools=[],
    )
    proposal = proposal_schema.validate(result)
    approval_id = approval_queue.create(actor.user_id, proposal)
    return {"approval_id": approval_id, "status": "pending_review"}
