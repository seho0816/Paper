"""
visualize_results.py
모든 run_eval_*.py + run_pairwise_eval.py 완료 후 실행.
result_int/ 폴더의 CSV를 읽어 논문용 그래프 4종 + Table 1 CSV를 생성한다.

생성 파일: result_int/figures/
  fig1_accuracy_bar.png    — Single & Pairwise Accuracy 비교
  fig2_metrics_radar.png   — Precision / Recall / F1 레이더
  fig3_cwe_heatmap.png     — CWE × 모델 오답 분포
  fig4_time_scatter.png    — Accuracy vs 추론시간 산점도
  table1_summary.csv       — 논문 Table 1 (직접 복사 가능)

의존: pip install matplotlib seaborn pandas
"""

import os
import csv
import glob
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import seaborn as sns
import numpy as np

from config import RESULT_DIR
from utils.metrics import compute as compute_metrics

FIGURE_DIR = os.path.join(RESULT_DIR, "figures")

# ── 모델 표시 순서 (논문 비교 순서와 동일) ──────────────────────
MODEL_ORDER = [
    "Bandit",
    "qwen2.5-coder_raw",
    "llama3.2_raw",
    "gemini-2.5-pro_raw",
    "qwen2.5-coder_simple_rag",
    "llama3.2_simple_rag",
    "gemini-2.5-pro_simple_rag",
    "qwen2.5-coder_rag",
    "llama3.2_rag",
    "gemini-2.5-pro_rag",
]

MODEL_LABELS = {
    "Bandit":                    "Bandit",
    "qwen2.5-coder_raw":         "Qwen\n(Raw)",
    "llama3.2_raw":              "Llama\n(Raw)",
    "gemini-2.5-pro_raw":        "Gemini\n(Raw)",
    "qwen2.5-coder_simple_rag":  "Qwen\n(SimpleRAG)",
    "llama3.2_simple_rag":       "Llama\n(SimpleRAG)",
    "gemini-2.5-pro_simple_rag": "Gemini\n(SimpleRAG)",
    "qwen2.5-coder_rag":         "Qwen\n(RAG)",
    "llama3.2_rag":              "Llama\n(RAG)",
    "gemini-2.5-pro_rag":        "Gemini\n(RAG)",
}

# 계열별 색상: Bandit=주황, Raw=회색, SimpleRAG=초록, RAG=파랑
MODEL_COLORS = {
    "Bandit":                    "#F4A261",
    "qwen2.5-coder_raw":         "#ADB5BD",
    "llama3.2_raw":              "#868E96",
    "gemini-2.5-pro_raw":        "#495057",
    "qwen2.5-coder_simple_rag":  "#95D5B2",
    "llama3.2_simple_rag":       "#52B788",
    "gemini-2.5-pro_simple_rag": "#1B4332",
    "qwen2.5-coder_rag":         "#74C0FC",
    "llama3.2_rag":              "#339AF0",
    "gemini-2.5-pro_rag":        "#1971C2",
}


# ── 한글 폰트 ─────────────────────────────────────────────────
def _set_korean_font():
    candidates = ['Malgun Gothic', 'Apple SD Gothic Neo',
                  'NanumGothic', 'NanumBarunGothic', 'DejaVu Sans']
    available = {f.name for f in fm.fontManager.ttflist}
    for font in candidates:
        if font in available:
            plt.rcParams['font.family'] = font
            break
    plt.rcParams['axes.unicode_minus'] = False

_set_korean_font()


# ════════════════════════════════════════════════════════════════
# 데이터 로더
# ════════════════════════════════════════════════════════════════

def load_data_csvs(result_dir: str) -> pd.DataFrame:
    frames = []
    for path in sorted(glob.glob(os.path.join(result_dir, "Data_*.csv"))):
        frames.append(pd.read_csv(path, encoding='utf-8-sig'))
    if not frames:
        raise FileNotFoundError(f"'{result_dir}' 에 Data_*.csv 없음.")
    return pd.concat(frames, ignore_index=True)


def load_pairwise_summary(result_dir: str):
    files = sorted(glob.glob(os.path.join(result_dir, "Pairwise_Summary_*.csv")))
    return pd.read_csv(files[-1], encoding='utf-8-sig') if files else None


def build_metrics_df(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for model in df['Model'].unique():
        sub  = df[df['Model'] == model].to_dict('records')
        m    = compute_metrics(sub)
        rows.append({'Model': model, **m})
    return pd.DataFrame(rows)


# ════════════════════════════════════════════════════════════════
# Figure 1: Accuracy + Pairwise Accuracy Bar chart
# ════════════════════════════════════════════════════════════════

def fig1_accuracy_bar(metrics_df, pairwise_df, save_path):
    models  = [m for m in MODEL_ORDER if m in metrics_df['Model'].values]
    labels  = [MODEL_LABELS.get(m, m) for m in models]
    colors  = [MODEL_COLORS.get(m, '#999') for m in models]
    acc     = [float(metrics_df.loc[metrics_df['Model']==m, 'Accuracy'].values[0]) for m in models]

    x     = np.arange(len(models))
    width = 0.38

    fig, ax = plt.subplots(figsize=(14, 5))
    bars1 = ax.bar(x - width/2, acc, width, label='Single Accuracy (%)',
                   color=colors, edgecolor='white', linewidth=0.8)

    if pairwise_df is not None:
        pair_acc = []
        for m in models:
            row = pairwise_df[pairwise_df['Model'] == m]
            pair_acc.append(float(row['Pairwise_Acc_%'].values[0]) if len(row) else 0)
        bars2 = ax.bar(x + width/2, pair_acc, width, label='Pairwise Accuracy (%)',
                       color=colors, edgecolor='white', linewidth=0.8, alpha=0.5, hatch='//')
        for bar, v in zip(bars2, pair_acc):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f"{v:.1f}", ha='center', va='bottom', fontsize=7, color='#333')

    for bar, v in zip(bars1, acc):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{v:.1f}", ha='center', va='bottom', fontsize=7, fontweight='bold')

    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Accuracy (%)", fontsize=11)
    ax.set_title("Figure 1. CWE Detection Accuracy by Model (Single & Pairwise)", fontsize=12)
    ax.legend(fontsize=9); ax.grid(axis='y', alpha=0.3)
    ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)

    # 계열 구분선: Raw | SimpleRAG | RAG
    raw_end    = sum(1 for m in models if m == 'Bandit' or '_raw' in m)
    simple_end = sum(1 for m in models if m == 'Bandit' or '_raw' in m or '_simple_rag' in m)
    for pos, label in [(raw_end - 0.5, 'Baseline │ Simple RAG'),
                       (simple_end - 0.5, 'Simple RAG │ Proposed')]:
        if 0 < pos < len(models) - 1:
            ax.axvline(x=pos, color='gray', linestyle='--', linewidth=1, alpha=0.5)
            ax.text(pos, 108, label, ha='center', fontsize=7, color='gray')

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  fig1 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# Figure 2: Precision / Recall / F1 Radar
# ════════════════════════════════════════════════════════════════

def fig2_metrics_radar(metrics_df, save_path):
    categories = ['Accuracy', 'Precision', 'Recall', 'F1']
    N = len(categories)
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]

    models = [m for m in MODEL_ORDER if m in metrics_df['Model'].values]
    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))

    for model in models:
        row    = metrics_df[metrics_df['Model'] == model].iloc[0]
        values = [float(row[c]) for c in categories] + [float(row[categories[0]])]
        ax.plot(angles, values, linewidth=1.8,
                color=MODEL_COLORS.get(model, '#999'),
                label=MODEL_LABELS.get(model, model).replace('\n', ' '))
        ax.fill(angles, values, alpha=0.06, color=MODEL_COLORS.get(model, '#999'))

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=11)
    ax.set_ylim(0, 100)
    ax.set_title("Figure 2. Precision / Recall / F1 by Model", fontsize=12, pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.4, 1.1), fontsize=7)

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  fig2 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# Figure 3: CWE × 모델 오답 분포 Heatmap
# ════════════════════════════════════════════════════════════════

def fig3_cwe_heatmap(df, save_path):
    vuln_df = df[df['Ground_Truth'] != 'None'].copy()
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

    fig, ax = plt.subplots(figsize=(max(12, len(models) * 1.3), max(5, len(cwes) * 0.65)))
    sns.heatmap(matrix, annot=True, fmt='d', cmap='YlOrRd',
                linewidths=0.5, linecolor='#eee', ax=ax,
                cbar_kws={'label': '오답 횟수'})
    ax.set_title("Figure 3. Error Distribution by CWE and Model", fontsize=12)
    ax.set_xlabel("Model", fontsize=10)
    ax.set_ylabel("CWE (Ground Truth)", fontsize=10)
    ax.tick_params(axis='x', labelsize=7, rotation=30)
    ax.tick_params(axis='y', labelsize=8, rotation=0)

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  fig3 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# Figure 4: Accuracy vs 추론시간 Scatter
# (메모리 제거 — 추론시간만 효율성 지표로 사용)
# ════════════════════════════════════════════════════════════════

def fig4_time_scatter(metrics_df, save_path):
    fig, ax = plt.subplots(figsize=(9, 5))

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
        ax.scatter(t, float(row['Accuracy']), color=color, s=120, zorder=5,
                   edgecolors='white', linewidth=0.8)
        ax.annotate(label, (t, float(row['Accuracy'])),
                    textcoords="offset points", xytext=(6, 4), fontsize=8)

    ax.set_xlabel("평균 추론 시간 (초/파일)", fontsize=11)
    ax.set_ylabel("Accuracy (%)", fontsize=11)
    ax.set_title("Figure 4. Accuracy vs. Average Inference Time per File", fontsize=12)
    ax.grid(alpha=0.3)
    ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  fig4 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# Table 1: 논문 집계 테이블
# ════════════════════════════════════════════════════════════════

def table1_summary(metrics_df, pairwise_df, save_path):
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
            'Model':            MODEL_LABELS.get(model, model).replace('\n', ' '),
            'Accuracy (%)':     m['Accuracy'],
            'Precision (%)':    m['Precision'],
            'Recall (%)':       m['Recall'],
            'F1 (%)':           m['F1'],
            'Pairwise Acc (%)': pair_acc,
            'Avg Time (s)':     m['Avg_Time_s'],
            'TP': m['TP'], 'TN': m['TN'], 'FP': m['FP'], 'FN': m['FN'],
        })

    with open(save_path, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"  table1 저장: {save_path}")


# ════════════════════════════════════════════════════════════════
# 메인
# ════════════════════════════════════════════════════════════════

def main():
    print("=== 논문용 시각화 생성 시작 ===\n")
    os.makedirs(FIGURE_DIR, exist_ok=True)

    print("CSV 로드 중...")
    try:
        df = load_data_csvs(RESULT_DIR)
    except FileNotFoundError as e:
        print(f"{e}"); return

    pairwise_df = load_pairwise_summary(RESULT_DIR)
    if pairwise_df is None:
        print("Pairwise_Summary 없음. run_pairwise_eval.py 먼저 실행 권장.")

    print(f"로드된 모델: {df['Model'].unique().tolist()}")
    print(f"총 {len(df)}행\n")

    metrics_df = build_metrics_df(df)
    print("지표 집계:")
    for _, row in metrics_df.iterrows():
        print(f"  {row['Model']:<35} Acc:{row['Accuracy']}% "
              f"P:{row['Precision']}% R:{row['Recall']}% F1:{row['F1']}%")
    print()

    print("Figure 생성 중...")
    fig1_accuracy_bar(metrics_df, pairwise_df,
                      os.path.join(FIGURE_DIR, "fig1_accuracy_bar.png"))
    fig2_metrics_radar(metrics_df,
                       os.path.join(FIGURE_DIR, "fig2_metrics_radar.png"))
    fig3_cwe_heatmap(df,
                     os.path.join(FIGURE_DIR, "fig3_cwe_heatmap.png"))
    fig4_time_scatter(metrics_df,
                      os.path.join(FIGURE_DIR, "fig4_time_scatter.png"))
    table1_summary(metrics_df, pairwise_df,
                   os.path.join(FIGURE_DIR, "table1_summary.csv"))

    print(f"\n완료! 저장 위치: {FIGURE_DIR}/")

if __name__ == "__main__":
    main()
