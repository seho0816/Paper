"""eval_grok_rag_ts.py — 제안 모델 ④: Grok 3 Mini + Tree-sitter RAG + MITRE"""
import os, time
from openai import OpenAI
from dotenv import load_dotenv
from config import MODEL_GROK_RAG_TS, GROK_MODEL
from rag_ts_engine import RAGEngine
from utils.scoring import predicted_cwe
from utils.prompts import build_rag, build_patch
from utils.loop import run

load_dotenv()
_key = os.getenv("GROK_API_KEY")
if not _key: print("GROK_API_KEY 없음"); exit()
_client = OpenAI(api_key=_key, base_url="https://api.x.ai/v1")

def main():
    print(f"=== [{MODEL_GROK_RAG_TS}] 초기화 (Tree-sitter RAG) ===")
    rag = RAGEngine()

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

    run(MODEL_GROK_RAG_TS, evaluate)

if __name__ == "__main__":
    main()