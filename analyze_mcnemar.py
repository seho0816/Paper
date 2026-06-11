"""
analyze_mcnemar.py
실험 완료 후 McNemar's Test로 통계적 유의성 검증.

사용법:
    python analyze_mcnemar.py  (result/ 폴더의 최신 CSV 자동 로드)
    python analyze_mcnemar.py --model1 gemini_rag_ts --model2 gemini

McNemar's Test: 동일 데이터셋에서 두 모델의 예측 결과가 통계적으로
유의미하게 다른지 검정. p < 0.05면 성능 차이가 우연이 아님을 의미.
"""
import os, csv, glob, itertools
from collections import defaultdict

RESULT_DIR = "result"

def load_latest_csvs():
    """result/의 최신 Data_*.csv 로드 → {model: {filename: match}}"""
    files = sorted(glob.glob(os.path.join(RESULT_DIR, "Data_*.csv")))
    latest = {}
    for p in files:
        base = os.path.basename(p)
        parts = base[5:-4].rsplit('_', 2)
        key = parts[0] if len(parts) == 3 else base
        if key not in latest or p > latest[key]:
            latest[key] = p
    results = {}
    for model, p in sorted(latest.items()):
        with open(p, encoding='utf-8-sig') as f:
            preds = {row['Filename']: row['Match'] for row in csv.DictReader(f)}
        results[model] = preds
        print(f"  로드: {os.path.basename(p)} ({len(preds)}개)")
    return results

def mcnemar_test(results_a, results_b):
    """두 모델의 McNemar 검정. (b01=A틀 B맞, b10=A맞 B틀)"""
    from scipy.stats import chi2
    common = set(results_a) & set(results_b)
    b01 = sum(1 for f in common if results_a[f]=='X' and results_b[f]=='O')
    b10 = sum(1 for f in common if results_a[f]=='O' and results_b[f]=='X')
    n = b01 + b10
    if n == 0:
        return 1.0, b01, b10
    # 연속성 수정 McNemar
    chi2_stat = (abs(b01 - b10) - 1) ** 2 / (b01 + b10)
    from scipy.stats import chi2 as chi2_dist
    p_val = 1 - chi2_dist.cdf(chi2_stat, df=1)
    return p_val, b01, b10

def main():
    print("=== McNemar's Test — 통계적 유의성 검정 ===\n")
    try:
        from scipy.stats import chi2
    except ImportError:
        print("scipy 필요: pip install scipy")
        return

    results = load_latest_csvs()
    if len(results) < 2:
        print("비교할 모델이 2개 이상 필요"); return

    models = sorted(results.keys())
    print(f"\n모델 수: {len(models)}개")
    print(f"{'모델 A':<30} {'모델 B':<30} {'p-value':>10} {'유의':>6} {'A↑B↓':>6} {'A↓B↑':>6}")
    print("-" * 85)

    # 제안 모델 vs 기타 비교를 우선, 나머지는 주요 쌍만
    priority_pairs = []
    rag_ts_models = [m for m in models if 'rag_ts' in m]
    raw_models    = [m for m in models if '_rag' not in m and m != 'bandit']
    rag_models    = [m for m in models if '_rag' in m and 'rag_ts' not in m]

    for ts in rag_ts_models:
        base = ts.replace('_rag_ts', '')
        for cmp in [f"{base}", f"{base}_rag", "bandit"]:
            if cmp in results:
                priority_pairs.append((ts, cmp))

    for a, b in priority_pairs:
        p, b01, b10 = mcnemar_test(results[a], results[b])
        sig = "***" if p < 0.001 else ("**" if p < 0.01 else ("*" if p < 0.05 else ""))
        print(f"  {a:<30} {b:<30} {p:>10.4f} {sig:>6} {b01:>6} {b10:>6}")

    print(f"\n  *** p<0.001  ** p<0.01  * p<0.05  (유의: A가 B보다 통계적으로 우수)")
    print(f"\n  A↑B↓: A만 맞힌 케이스 수 (A 고유 기여)")
    print(f"  A↓B↑: B만 맞힌 케이스 수 (B 고유 기여)")

if __name__ == "__main__":
    main()