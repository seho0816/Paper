import os

# 평가 대상 모델
MODELS = [
    'qwen2.5-coder',
    'llama3.2',
    'gemini-2.5-pro'
]

# 경로 설정
TEST_DIR = 'py_dataset'      # 분석 대상 폴더
KNOWLEDGE_DIR = 'knowledge'  # CWE JSON 폴더
DB_DIR = 'rag_db'            # ChromaDB 저장 폴더

# DB 설정
COLLECTION_NAME = 'python_security_lessons'
DISTANCE_THRESHOLD = 1.5
MAX_RETRIEVAL_K = 1