"""eval_gemini_rag_ts.py — 제안 모델 ④: Gemini + Tree-sitter RAG + MITRE"""

    # ── 실행 옵션 ──────────────────────────────────────────────
    # python eval_gemini_rag_ts.py                    전체 평가
    # python eval_gemini_rag_ts.py --limit 10         앞에서 10개만
    # python eval_gemini_rag_ts.py --sample 5         무작위 5쌍
    # python eval_gemini_rag_ts.py --resume           중단 후 이어하기
    # python eval_gemini_rag_ts.py --folder 00        00_legacy_db_derived만
    # python eval_gemini_rag_ts.py --folder 01        01_regression만
    # python eval_gemini_rag_ts.py --folder 02        02_semantic_generalization만
    # python eval_gemini_rag_ts.py --folder 03        03_structural_generalization만
    # python eval_gemini_rag_ts.py --folder 04        04_safe_boundary만
    # python eval_gemini_rag_ts.py --folder 05        05_external_independent만
    # python eval_gemini_rag_ts.py --folder 01 --sample 10   조합 가능
    # ────────────────────────────────────────────────────────────

import argparse as _ap
import os, time
from google import genai
from dotenv import load_dotenv
from config import MODEL_GEMINI_RAG, GEMINI_MODEL
from rag_ts_engine import RAGEngine
from utils.scoring import predicted_cwe
from utils.prompts import build_rag, build_patch
from utils.loop import run
from utils.retry import raise_if_rate_limit

load_dotenv()
_key = os.getenv("GEMINI_API_KEY")
if not _key: print("GEMINI_API_KEY 없음"); exit()
_client = genai.Client(api_key=_key)

def main():
    print(f"=== [{MODEL_GEMINI_RAG}] 초기화 (Tree-sitter RAG) ===")
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
            r = _client.models.generate_content(
                model=GEMINI_MODEL, contents=prompt)
            text = r.text if r.text is not None else ""
        except Exception as e:
            print(f"\n    ⚠️  API 오류: {e}", flush=True)
            raise_if_rate_limit(e)
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2), allowed)
    
    _p = _ap.ArgumentParser()
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _p.add_argument('--resume', action='store_true', help='중단된 평가 이어하기')
    _p.add_argument('--folder', type=str, default='',
                    help='특정 폴더만 평가 (예: 01, 02_semantic, safe_boundary)')
    _args = _p.parse_args()
    run(MODEL_GEMINI_RAG, evaluate, "gemini_rag_ts", limit=_args.limit, sample=_args.sample,
        resume=_args.resume,
        folder_filter=_args.folder)

if __name__ == "__main__":
    main()