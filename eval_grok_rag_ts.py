"""eval_grok_rag_ts.py — 제안 모델 ④: Grok 3 Mini + Tree-sitter RAG + MITRE"""
import os, time
from openai import OpenAI
from dotenv import load_dotenv
from config import MODEL_GROK_RAG_TS, GROK_MODEL
from rag_ts_engine import RAGEngine
from utils.scoring import predicted_cwe
from utils.prompts import build_rag, build_patch
from utils.loop import run
from utils.retry import raise_if_rate_limit

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
                max_tokens=2048,
                temperature=0.0
            )
            text = r.choices[0].message.content or ""
        except Exception as e:
            print(f"\n    ⚠️  API 오류 [eval_grok_rag_ts.py]: {e}", flush=True)
            raise_if_rate_limit(e)
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    # ── 실행 옵션 ──────────────────────────────────────────────
    # 전체 평가:           python eval_grok_rag_ts.py
    # 앞에서 N개만:        python eval_grok_rag_ts.py --limit 10
    # 무작위 N쌍 샘플:     python eval_grok_rag_ts.py --sample 5
    #   (--sample은 test/patch 쌍 단위로 무작위 선택 → 균형 보장)
    # ────────────────────────────────────────────────────────────
    import argparse as _ap
    _p = _ap.ArgumentParser(description="eval_grok_rag_ts 평가")
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _args = _p.parse_args()
    run(MODEL_GROK_RAG_TS, evaluate, "grok_rag_ts", limit=_args.limit, sample=_args.sample)

if __name__ == "__main__":
    main()