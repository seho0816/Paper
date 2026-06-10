"""eval_llama.py — 비교군 ②: Llama 3.2, 순수 LLM"""

# ── 실행 옵션 ──────────────────────────────────────────────
# python eval_llama.py                    전체 평가
# python eval_llama.py --limit 10         앞에서 10개만
# python eval_llama.py --sample 5         무작위 5쌍
# python eval_llama.py --resume           중단 후 이어하기
# python eval_llama.py --folder 00        00_legacy_db_derived만
# python eval_llama.py --folder 01        01_regression만
# python eval_llama.py --folder 02        02_semantic_generalization만
# python eval_llama.py --folder 03        03_structural_generalization만
# python eval_llama.py --folder 04        04_safe_boundary만
# python eval_llama.py --folder 05        05_external_independent만
# python eval_llama.py --folder 01 --sample 10   조합 가능
# ────────────────────────────────────────────────────────────

import time, ollama
from config import MODEL_LLAMA_RAW, OLLAMA_LLAMA, OLLAMA_OPTIONS
from utils.scoring import predicted_cwe
from utils.prompts import build_raw_en, build_patch_en
from utils.loop import run

def main():
    def evaluate(code, is_patch=False):
        prompt = build_patch_en(code) if is_patch else build_raw_en(code)
        start = time.time()
        try:
            r = ollama.chat(model=OLLAMA_LLAMA,
                            messages=[{'role':'user','content':prompt}],
                            options=OLLAMA_OPTIONS)
            text = r['message']['content'] or ""
        except Exception as e:
            print(f"\n    ⚠️  API 오류 [eval_llama.py]: {e}", flush=True)
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))
    import argparse as _ap
    _p = _ap.ArgumentParser()
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _p.add_argument('--resume', action='store_true', help='중단된 평가 이어하기')
    _p.add_argument('--folder', type=str, default='',
                    help='특정 폴더만 평가 (예: 01, 02_semantic, safe_boundary)')
    _args = _p.parse_args()
    run(MODEL_LLAMA_RAW, evaluate, "llama", limit=_args.limit, sample=_args.sample,
        resume=_args.resume,
        folder_filter=_args.folder)

if __name__ == "__main__":
    main()