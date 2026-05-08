import os
import chromadb
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
# config에서 필요한 변수들을 가져옵니다.
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
            # 💡 중요: build_db는 텍스트를 'documents' 필드에 저장했습니다.
            results = self.collection.query(query_texts=[chunk], n_results=k)
            
            if results['documents'] and results['documents'][0]:
                distances = results['distances'][0]
                documents = results['documents'][0] # 메타데이터가 아닌 문서를 직접 가져옵니다.
                
                for j in range(len(documents)):
                    if distances[j] < DISTANCE_THRESHOLD:
                        # 💡 metadatas[j]['full_text'] 대신 documents[j]를 사용합니다.
                        retrieved_contexts_set.add(documents[j])
        
        if not retrieved_contexts_set: 
            return ""
        
        return "\n\n".join([f"--- [보안 지식 참고자료 {idx+1}] ---\n{doc}" for idx, doc in enumerate(retrieved_contexts_set)])