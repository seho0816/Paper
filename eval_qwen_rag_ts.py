"""eval_qwen_rag_ts.py — 제안 모델 ④: Qwen + Tree-sitter RAG + MITRE"""
import time, ollama
from config import MODEL_QWEN_RAG, OLLAMA_QWEN, OLLAMA_OPTIONS
from rag_ts_engine import RAGEngine
from utils.scoring import predicted_cwe
from utils.prompts import build_rag_en, build_patch_en
from utils.loop import run

def main():
    print(f"=== [{MODEL_QWEN_RAG}] 초기화 (Tree-sitter RAG) ===")
    rag = RAGEngine()

    def evaluate(code, is_patch=False):
        # get_context_local(): 한국어 RAG 컨텍스트를 영어 요약으로 압축
        # → 토큰 대폭 감소, 로컬 모델 영어 응답 유도, 속도 개선
        rag_ctx, mitre_ctx, allowed = rag.get_context_local(code)
        if is_patch:
            prompt = build_patch_en(code, rag_ctx, mitre_ctx)
        else:
            if not rag_ctx: return ("SKIPPED", 0.0)
            prompt = build_rag_en(code, rag_ctx, mitre_ctx, allowed)
        start = time.time()
        try:
            r = ollama.chat(
                model=OLLAMA_QWEN,
                messages=[{'role':'user','content':prompt}],
                options=OLLAMA_OPTIONS
            )
            text = r['message']['content']
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    run(MODEL_QWEN_RAG, evaluate)

if __name__ == "__main__":
    main()