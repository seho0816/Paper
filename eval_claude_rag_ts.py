"""eval_claude_rag_ts.py — 제안 모델 ④: Claude + Tree-sitter RAG + MITRE"""
import os, time
import anthropic
from dotenv import load_dotenv
from config import MODEL_CLAUDE_RAG_TS, CLAUDE_MODEL
from rag_ts_engine import RAGEngine
from utils.scoring import predicted_cwe
from utils.prompts import build_rag, build_patch
from utils.loop import run

load_dotenv()
_key = os.getenv("CLAUDE_API_KEY")
if not _key: print("CLAUDE_API_KEY 없음"); exit()
_client = anthropic.Anthropic(api_key=_key)

def main():
    print(f"=== [{MODEL_CLAUDE_RAG_TS}] 초기화 (Tree-sitter RAG) ===")
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
            msg = _client.messages.create(
                model=CLAUDE_MODEL, max_tokens=2048, temperature=0.0,
                messages=[{"role": "user", "content": prompt}]
            )
            text = msg.content[0].text if msg.content else ""
        except Exception as e:
            print(f"\n    ⚠️  API 오류 [eval_claude_rag_ts.py]: {e}", flush=True)
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    # ── 실행 옵션 ──────────────────────────────────────────────
    # 전체 평가:           python eval_claude_rag_ts.py
    # 앞에서 N개만:        python eval_claude_rag_ts.py --limit 10
    # 무작위 N쌍 샘플:     python eval_claude_rag_ts.py --sample 5
    # ────────────────────────────────────────────────────────────
    import argparse as _ap
    _p = _ap.ArgumentParser(description="claude_rag_ts 평가")
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _args = _p.parse_args()
    run(MODEL_CLAUDE_RAG_TS, evaluate, "claude_rag_ts",
        limit=_args.limit, sample=_args.sample)

if __name__ == "__main__":
    main()