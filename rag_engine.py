import os
import chromadb
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
from config import DB_DIR, COLLECTION_NAME, DISTANCE_THRESHOLD, MAX_RETRIEVAL_K

class RAGEngine:
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(current_dir, DB_DIR)
        self.db_client = chromadb.PersistentClient(path=db_path)
        self.collection = self.db_client.get_collection(name=COLLECTION_NAME)
        self.parser = Parser()
        self.parser.language = Language(tspython.language())

    def _extract_functions(self, node, source_code, chunks_list):
        if node.type in ["function_definition", "class_definition"]:
            chunks_list.append(source_code[node.start_byte:node.end_byte])
        elif node.type == "if_statement" and node.parent and node.parent.type == "module":
            chunks_list.append(source_code[node.start_byte:node.end_byte])
        for child in node.children:
            self._extract_functions(child, source_code, chunks_list)

    def _chunk_code(self, source_code):
        tree = self.parser.parse(bytes(source_code, "utf8"))
        functions = []
        self._extract_functions(tree.root_node, source_code, functions)
        return functions if functions else [source_code]

    def get_context(self, user_code):
        chunks = self._chunk_code(user_code)
        retrieved_contexts_set = set()
        db_size = self.collection.count()
        if db_size == 0: return ""
            
        k = min(MAX_RETRIEVAL_K, db_size)
        for chunk in chunks:
            results = self.collection.query(query_texts=[chunk], n_results=k)
            if results['metadatas'] and results['metadatas'][0]:
                distances = results['distances'][0]
                metadatas = results['metadatas'][0]
                for j in range(len(metadatas)):
                    if distances[j] < DISTANCE_THRESHOLD:
                        retrieved_contexts_set.add(metadatas[j]['full_text'])
        
        if not retrieved_contexts_set: return ""
        return "\n\n".join([f"--- [참고 지식 {idx+1}] ---\n{doc}" for idx, doc in enumerate(retrieved_contexts_set)])