"""eval_grok_rag.py — 비교군 ③: Grok 3 Mini + 라인 단위 RAG"""
import os, time
from openai import OpenAI
from dotenv import load_dotenv
from config import MODEL_GROK_SIMPLE_RAG, GROK_MODEL
from rag_engine import SimpleRAGEngine
from utils.scoring import predicted_cwe
from utils.prompts import build_rag, build_patch
from utils.loop import run

load_dotenv()
_key = os.getenv("GROK_API_KEY")
if not _key: print("GROK_API_KEY 없음"); exit()
_client = OpenAI(api_key=_key, base_url="https://api.x.ai/v1")

def main():
    print(f"=== [{MODEL_GROK_SIMPLE_RAG}] 초기화 (라인 단위 RAG) ===")
    rag = SimpleRAGEngine()

    def evaluate(code, is_patch=False):
        rag_ctx, mitre_ctx, allowed = rag.get_context(code)
        if is_patch:
            prompt = build_patch(code, rag_ctx, mitre_ctx)
        else:
            if not rag_ctx: return ("SKIPPED", 0.0)
            prompt = build_rag(code, rag_ctx, mitre_ctx, allowed)
        start = time.time()
        try:
            r = _client.chat.completions.create(
                model=GROK_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024
            )
            text = r.choices[0].message.content
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    run(MODEL_GROK_SIMPLE_RAG, evaluate, "grok_rag")

if __name__ == "__main__":
    main()