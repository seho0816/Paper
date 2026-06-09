class RetrievalPipeline:
    def __init__(
        self,
        retriever,
        agent,
        tool_executor,
    ) -> None:
        self._retriever = retriever
        self._agent = agent
        self._tool_executor = tool_executor

    def answer_and_act(
        self,
        query: str,
    ) -> str:
        documents = self._retriever.search(
            query
        )
        context = '\n\n'.join(
            document.text
            for document in documents
        )
        result = self._agent.run(
            prompt=(
                'Use the retrieved instructions to resolve the request.\n'
                + context
            ),
            tools=ADMINISTRATIVE_TOOLS,
        )

        for call in result.tool_calls:
            self._tool_executor.execute(
                call.name,
                call.arguments,
            )

        return result.text
