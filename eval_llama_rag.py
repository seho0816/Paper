"""eval_llama_rag.py — 비교군 ③: Llama 3.2 + 라인 단위 RAG"""
import time, ollama
from config import MODEL_LLAMA_SIMPLE_RAG, OLLAMA_LLAMA, OLLAMA_OPTIONS
from rag_engine import SimpleRAGEngine
from utils.scoring import predicted_cwe
from utils.prompts import build_rag_en, build_patch_en
from utils.loop import run

def main():
    print(f"=== [{MODEL_LLAMA_SIMPLE_RAG}] 초기화 (라인 단위 RAG) ===")
    rag = SimpleRAGEngine()

    def evaluate(code, is_patch=False):
        rag_ctx, mitre_ctx, allowed = rag.get_context(code)
        if is_patch:
            prompt = build_patch_en(code, rag_ctx, mitre_ctx)
        else:
            if not rag_ctx: return ("SKIPPED", 0.0)
            prompt = build_rag_en(code, rag_ctx, mitre_ctx, allowed)
        start = time.time()
        try:
            r = ollama.chat(model=OLLAMA_LLAMA, messages=[{'role':'user','content':prompt}], options=OLLAMA_OPTIONS)
            text = r['message']['content']
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    run(MODEL_LLAMA_SIMPLE_RAG, evaluate)

if __name__ == "__main__":
    main()
