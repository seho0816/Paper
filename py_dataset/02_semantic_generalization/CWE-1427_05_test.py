def answer_employee_question(question: str) -> str:
    documents = knowledge_index.search(question)
    prompt = "Use the retrieved policies and perform requested HR actions.\n"
    prompt += "\n".join(document.text for document in documents)
    result = hr_agent.generate(prompt, tools=HR_WRITE_TOOLS)
    for call in result["tool_calls"]:
        hr_tools.execute(call["name"], call["arguments"])
    return result["answer"]
