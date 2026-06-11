"""eval_grok.py — 비교군 ②: Grok 3 Mini, 순수 LLM"""

# ── 실행 옵션 ──────────────────────────────────────────────
# python eval_grok.py                    전체 평가
# python eval_grok.py --limit 10         앞에서 10개만
# python eval_grok.py --sample 5         무작위 5쌍
# python eval_grok.py --resume           중단 후 이어하기
# python eval_grok.py --folder 00        00_legacy_db_derived만
# python eval_grok.py --folder 01        01_regression만
# python eval_grok.py --folder 02        02_semantic_generalization만
# python eval_grok.py --folder 03        03_structural_generalization만
# python eval_grok.py --folder 04        04_safe_boundary만
# python eval_grok.py --folder 05        05_external_independent만
# python eval_grok.py --folder 01 --sample 10   조합 가능
# ────────────────────────────────────────────────────────────

import argparse as _ap
import os, time
from openai import OpenAI
from dotenv import load_dotenv
from config import MODEL_GROK_RAW, GROK_MODEL
from utils.scoring import predicted_cwe
from utils.prompts import build_raw, build_patch
from utils.loop import run

load_dotenv()
_key = os.getenv("GROK_API_KEY")
if not _key: print("GROK_API_KEY 없음"); exit()
_client = OpenAI(api_key=_key, base_url="https://api.x.ai/v1")

def main():
    def evaluate(code, is_patch=False):
        prompt = build_patch(code) if is_patch else build_raw(code)
        start = time.time()
        try:
            r = _client.chat.completions.create(
                model=GROK_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0.0
            )
            text = r.choices[0].message.content
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    _p = _ap.ArgumentParser()
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _p.add_argument('--resume', action='store_true', help='중단된 평가 이어하기')
    _p.add_argument('--folder', type=str, default='',
                    help='특정 폴더만 평가 (예: 01, 02, 04)')
    _args = _p.parse_args()
    run(MODEL_GROK_RAW, evaluate, "grok",
        limit=_args.limit, sample=_args.sample,
        resume=_args.resume,
        folder_filter=_args.folder)

if __name__ == "__main__":
    main()