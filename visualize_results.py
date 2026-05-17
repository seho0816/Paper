"""
visualize_results.py
====================
모든 실험 완료 후 result_int/ 폴더의 CSV를 읽어
논문용 그래프 4종을 자동 생성한다.

[생성 파일]
  result_int/figures/
    fig1_accuracy_bar.png       — 모델별 Accuracy / Pairwise Accuracy 비교 Bar chart
    fig2_metrics_radar.png      — Precision / Recall / F1 Spider chart (레이더)
    fig3_cwe_heatmap.png        — CWE × 모델 오답 분포 Heatmap
    fig4_time_scatter.png       — Accuracy vs 평균 추론 시간 Scatter plot
    table1_summary.csv          — 논문 Table 1 직접 복사 가능한 집계 CSV

실행:
    python visualize_results.py
  (모든 run_eval_*.py + run_pairwise_eval.py 완료 후)

의존:
    pip install matplotlib seaborn pandas
"""

import os
import csv
import glob
import datetime
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import matplotlib
matplotlib.use('Agg')   # GUI 없는 서버 환경 대응
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import seaborn as sns
import numpy as np

from config import RESULT_DIR
from utils.eval_utils import compute_metrics

# ── 한글 폰트 설정 (Windows/Mac/Linux 공통) ──────────────────────
def _set_korean_font():
    candidates = [
        'Malgun Gothic', 'Apple SD Gothic Neo', 'NanumGothic',
        'NanumBarunGothic', 'DejaVu Sans'
    ]
    available = {f.name for f in fm.fontManager.ttflist}
    for font in candidates:
        if font in available:
            plt.rcParams['font.family'] = font
            break
    plt.rcParams['axes.unicode_minus'] = False

_set_korean_font()

FIGURE_DIR = os.path.join(RESULT_DIR, "figures")

# 모델 표시 순서 (논문 표기 순)
MODEL_ORDER = [
    "Bandit",
    "qwen2.5-coder_raw",
    "llama3.2_raw",
    "gemini-2.5-pro_raw",
    "qwen2.5-coder_rag",
    "llama3.2_rag",
    "gemini-2.5-pro_rag",
]

# 논문용 모델 약칭
MODEL_LABELS = {
    "Bandit":               "Bandit",
    "qwen2.5-coder_raw":    "Qwen\n(Raw)",
    "llama3.2_raw":         "Llama\n(Raw)",
    "gemini-2.5-pro_raw":   "Gemini\n(Raw)",
    "qwen2.5-coder_rag":    "Qwen\n(RAG)",
    "llama3.2_rag":         "Llama\n(RAG)",
    "gemini-2.5-pro_rag":   "Gemini\n(RAG)",
}

# 색상: Raw=회색 계열, RAG=파랑 계열, Bandit=주황
MODEL_COLORS = {
    "Bandit":               "#F4A261",
    "qwen2.5-coder_raw":    "#ADB5BD",
    "llama3.2_raw":         "#868E96",
    "gemini-2.5-pro_raw":   "#495057",
    "qwen2.5-coder_rag":    "#74C0FC",
    "llama3.2_rag":         "#339AF0",
    "gemini-2.5-pro_rag":   "#1971C2",
}


# ════════════════════════════════════════════════════════════════
# 데이터 로더
# ════════════════════════════════════════════════════════════════

def load_data_csvs(result_dir: str) -> pd.DataFrame:
    """Data_*.csv 전부 합쳐 DataFrame 반환."""
    frames = []
    for path in sorted(glob.glob(os.path.join(result_dir, "Data_*.csv"))):
        df = pd.read_csv(path, encoding='utf-8-sig')
        frames.append(df)
    if not frames:
        raise FileNotFoundError(f"'{result_dir}' 에 Data_*.csv 없음.")
    return pd.concat(frames, ignore_index=True)


def load_pairwise_summary(result_dir: str) -> pd.DataFrame | None:
    """가장 최근 Pairwise_Summary_*.csv 반환."""
    files = sorted(glob.glob(os.path.join(result_dir, "Pairwise_Summary_*.csv")))
    if not files:
        return None
    return pd.read_csv(files[-1], encoding='utf-8-sig')


def build_metrics_table(df: pd.DataFrame) -> pd.DataFrame:
    """모델별 지표를 집계하여 DataFrame 반환."""
    rows = []
    for model in df['Model'].unique():
        sub   = df[df['Model'] == model].to_dict('records')
        m     = compute_metrics(sub)
        avg_t = df[df['Model'] == model]['Time_s'].mean()
        rows.append({'Model': model, **m, 'Avg_Time_s': round(avg_t, 2)})
    return pd.DataFrame(rows)


# ════════════════════════════════════════════════════════════════
# Figure 1: Accuracy + Pairwise Accuracy Bar chart
# ════════════════════════════════════════════════════════════════

def fig1_accuracy_bar(metrics_df: pd.DataFrame, pairwise_df: pd.DataFrame | None,
                      save_path: str) -> None:
    models  = [m for m in MODEL_ORDER if m in metrics_df['Model'].values]
    labels  = [MODEL_LABELS.get(m, m) for m in models]
    colors  = [MODEL_COLORS.get(m, '#999') for m in models]
    acc     = [metrics_df.loc[metrics_df['Model']==m, 'Accuracy'].values[0] for m in models]

    x = np.arange(len(models))
    width = 0.38

    fig, ax = plt.subplots(figsize=(12, 5))

    bars1 = ax.bar(x - width/2, acc, width, label='Single Accuracy (%)',
                   color=colors, edgecolor='white', linewidth=0.8)

    if pairwise_df is not None:
        pair_acc = []
        for m in models:
            row = pairwise_df[pairwise_df['Model'] == m]
            pair_acc.append(float(row['Pairwise_Acc_%'].values[0]) if len(row) else 0)
        bars2 = ax.bar(x + width/2, pair_acc, width, label='Pairwise Accuracy (%)',
                       color=colors, edgecolor='white', linewidth=0.8, alpha=0.55, hatch='//')
        for bar, v in zip(bars2, pair_acc):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f"{v:.1f}", ha='center', va='bottom', fontsize=8, color='#333')

    for bar, v in zip(bars1, acc):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{v:.1f}", ha='center', va='bottom', fontsize=8, fontweight='bold')

    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Accuracy (%)", fontsize=11)
    ax.set_title("Figure 1. CWE Detection Accuracy by Model\n(Single & Pairwise)", fontsize=12)
    ax.legend(fontsize=9); ax.grid(axis='y', alpha=0.3)
    ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)

    # RAG/Raw 구분선
    raw_end = sum(1 for m in models if 'raw' in m or m == 'Bandit')
    if raw_end < len(models):
        ax.axvline(x=raw_end - 0.5, color='gray', linestyle='--', linewidth=1, alpha=0.6)
        ax.text(raw_end - 0.5, 108, 'Baseline │ Proposed', ha='center', fontsize=8, color='gray')

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  ✅ fig1 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# Figure 2: Precision / Recall / F1 Radar chart
# ════════════════════════════════════════════════════════════════

def fig2_metrics_radar(metrics_df: pd.DataFrame, save_path: str) -> None:
    categories = ['Accuracy', 'Precision', 'Recall', 'F1']
    N = len(categories)
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]

    models = [m for m in MODEL_ORDER if m in metrics_df['Model'].values]
    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))

    for model in models:
        row    = metrics_df[metrics_df['Model'] == model].iloc[0]
        values = [row[c] for c in categories] + [row[categories[0]]]
        ax.plot(angles, values, linewidth=1.8,
                color=MODEL_COLORS.get(model, '#999'),
                label=MODEL_LABELS.get(model, model))
        ax.fill(angles, values, alpha=0.07, color=MODEL_COLORS.get(model, '#999'))

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=11)
    ax.set_ylim(0, 100)
    ax.set_title("Figure 2. Precision / Recall / F1 by Model", fontsize=12, pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.35, 1.1), fontsize=8)

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  ✅ fig2 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# Figure 3: CWE × 모델 오답 분포 Heatmap
# ════════════════════════════════════════════════════════════════

def fig3_cwe_heatmap(df: pd.DataFrame, save_path: str) -> None:
    """
    X축: 모델, Y축: CWE (Ground Truth)
    셀값: 해당 CWE에서 모델이 틀린 횟수 (FP + FN)
    패치 파일(GT=None)은 제외.
    """
    vuln_df = df[df['Ground_Truth'] != 'None'].copy()
    # 복수 CWE는 첫 번째 CWE 기준
    vuln_df['Primary_GT'] = vuln_df['Ground_Truth'].apply(lambda x: x.split('/')[0])

    models = [m for m in MODEL_ORDER if m in vuln_df['Model'].unique()]
    cwes   = sorted(vuln_df['Primary_GT'].unique())

    matrix = pd.DataFrame(0, index=cwes, columns=models)
    for _, row in vuln_df.iterrows():
        if row['Match'] == 'X' and row['Model'] in matrix.columns:
            cwe = row['Primary_GT']
            if cwe in matrix.index:
                matrix.loc[cwe, row['Model']] += 1

    col_labels = [MODEL_LABELS.get(m, m).replace('\n', ' ') for m in models]
    matrix.columns = col_labels

    fig, ax = plt.subplots(figsize=(max(10, len(models) * 1.4), max(6, len(cwes) * 0.7)))
    sns.heatmap(matrix, annot=True, fmt='d', cmap='YlOrRd',
                linewidths=0.5, linecolor='#eee',
                ax=ax, cbar_kws={'label': '오답 횟수'})
    ax.set_title("Figure 3. Error Distribution by CWE and Model", fontsize=12)
    ax.set_xlabel("Model", fontsize=10)
    ax.set_ylabel("CWE (Ground Truth)", fontsize=10)
    ax.tick_params(axis='x', labelsize=8, rotation=30)
    ax.tick_params(axis='y', labelsize=8, rotation=0)

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  ✅ fig3 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# Figure 4: Accuracy vs 평균 추론 시간 Scatter plot
# ════════════════════════════════════════════════════════════════

def fig4_time_scatter(metrics_df: pd.DataFrame, save_path: str) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))

    for _, row in metrics_df.iterrows():
        model = row['Model']
        try:
            t = float(row['Avg_Time_s'])
        except (ValueError, TypeError):
            continue
        if t <= 0:
            continue

        color = MODEL_COLORS.get(model, '#999')
        label = MODEL_LABELS.get(model, model).replace('\n', ' ')
        ax.scatter(t, row['Accuracy'], color=color, s=120, zorder=5,
                   edgecolors='white', linewidth=0.8)
        ax.annotate(label, (t, row['Accuracy']),
                    textcoords="offset points", xytext=(6, 4), fontsize=8)

    ax.set_xlabel("평균 추론 시간 (초/파일)", fontsize=11)
    ax.set_ylabel("Accuracy (%)", fontsize=11)
    ax.set_title("Figure 4. Accuracy vs. Inference Time per File", fontsize=12)
    ax.grid(alpha=0.3)
    ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  ✅ fig4 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# Table 1: 논문 집계 테이블 CSV
# ════════════════════════════════════════════════════════════════

def table1_summary(metrics_df: pd.DataFrame,
                   pairwise_df: pd.DataFrame | None,
                   save_path: str) -> None:
    """
    논문 Table 1로 직접 사용 가능한 형태의 CSV.
    열: Model | Accuracy | Precision | Recall | F1 | Pairwise_Acc | Avg_Time_s
    """
    rows = []
    for model in MODEL_ORDER:
        m_row = metrics_df[metrics_df['Model'] == model]
        if m_row.empty:
            continue
        m = m_row.iloc[0]

        pair_acc = "N/A"
        if pairwise_df is not None:
            p_row = pairwise_df[pairwise_df['Model'] == model]
            if not p_row.empty:
                pair_acc = p_row.iloc[0]['Pairwise_Acc_%']

        rows.append({
            'Model':          MODEL_LABELS.get(model, model).replace('\n', ' '),
            'Accuracy (%)':   m['Accuracy'],
            'Precision (%)':  m['Precision'],
            'Recall (%)':     m['Recall'],
            'F1 (%)':         m['F1'],
            'Pairwise Acc (%)': pair_acc,
            'Avg Time (s)':   m['Avg_Time_s'],
            'TP':             m['TP'],
            'TN':             m['TN'],
            'FP':             m['FP'],
            'FN':             m['FN'],
        })

    with open(save_path, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"  ✅ table1 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# 메인
# ════════════════════════════════════════════════════════════════

def main():
    print("=== 📊 논문용 시각화 생성 시작 ===\n")
    os.makedirs(FIGURE_DIR, exist_ok=True)

    # 데이터 로드
    print("📂 CSV 로드 중...")
    try:
        df = load_data_csvs(RESULT_DIR)
    except FileNotFoundError as e:
        print(f"❌ {e}"); return

    pairwise_df = load_pairwise_summary(RESULT_DIR)
    if pairwise_df is None:
        print("⚠️  Pairwise_Summary_*.csv 없음. run_pairwise_eval.py 먼저 실행 권장.")

    print(f"   로드된 모델: {df['Model'].unique().tolist()}")
    print(f"   총 행 수: {len(df)}\n")

    # 지표 집계
    metrics_df = build_metrics_table(df)
    print("📈 지표 집계 완료:")
    for _, row in metrics_df.iterrows():
        print(f"   {row['Model']:<35} Acc:{row['Accuracy']}% "
              f"P:{row['Precision']}% R:{row['Recall']}% F1:{row['F1']}%")
    print()

    # Figure 생성
    print("🎨 Figure 생성 중...")
    fig1_accuracy_bar(
        metrics_df, pairwise_df,
        os.path.join(FIGURE_DIR, "fig1_accuracy_bar.png")
    )
    fig2_metrics_radar(
        metrics_df,
        os.path.join(FIGURE_DIR, "fig2_metrics_radar.png")
    )
    fig3_cwe_heatmap(
        df,
        os.path.join(FIGURE_DIR, "fig3_cwe_heatmap.png")
    )
    fig4_time_scatter(
        metrics_df,
        os.path.join(FIGURE_DIR, "fig4_time_scatter.png")
    )
    table1_summary(
        metrics_df, pairwise_df,
        os.path.join(FIGURE_DIR, "table1_summary.csv")
    )

    print(f"\n✅ 전체 완료! 저장 위치: {FIGURE_DIR}/")
    print("   fig1_accuracy_bar.png   — 논문 Figure 1 (Accuracy 비교 Bar chart)")
    print("   fig2_metrics_radar.png  — 논문 Figure 2 (P/R/F1 Radar chart)")
    print("   fig3_cwe_heatmap.png    — 논문 Figure 3 (CWE 오답 Heatmap)")
    print("   fig4_time_scatter.png   — 논문 Figure 4 (정확도 vs 추론시간 Scatter)")
    print("   table1_summary.csv      — 논문 Table 1 (직접 복붙 가능)")


if __name__ == "__main__":
    main()
