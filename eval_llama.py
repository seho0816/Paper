"""eval_llama.py — 비교군 ②: Llama 3.2, 순수 LLM"""
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
            text = r['message']['content']
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    # ── 실행 옵션 ──────────────────────────────────────────────
    # 전체 평가:           python eval_llama.py
    # 앞에서 N개만:        python eval_llama.py --limit 10
    # 무작위 N쌍 샘플:     python eval_llama.py --sample 5
    #   (--sample은 test/patch 쌍 단위로 무작위 선택 → 균형 보장)
    # ────────────────────────────────────────────────────────────
    import argparse as _ap
    _p = _ap.ArgumentParser(description="llama 평가")
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _args = _p.parse_args()
    run(MODEL_LLAMA_RAW, evaluate, "llama", limit=_args.limit, sample=_args.sample)

if __name__ == "__main__":
    main()