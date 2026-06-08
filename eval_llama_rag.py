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
                model=OLLAMA_LLAMA,
                messages=[{'role':'user','content':prompt}],
                options=OLLAMA_OPTIONS
            )
            text = r['message']['content']
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    # ── 실행 옵션 ──────────────────────────────────────────────
    # 전체 평가:           python eval_llama_rag.py
    # 앞에서 N개만:        python eval_llama_rag.py --limit 10
    # 무작위 N쌍 샘플:     python eval_llama_rag.py --sample 5
    #   (--sample은 test/patch 쌍 단위로 무작위 선택 → 균형 보장)
    # ────────────────────────────────────────────────────────────
    import argparse as _ap
    _p = _ap.ArgumentParser(description="eval_llama_rag 평가")
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _args = _p.parse_args()
    run(MODEL_LLAMA_SIMPLE_RAG, evaluate, "llama", limit=_args.limit, sample=_args.sample)

if __name__ == "__main__":
    main()