import os
import datetime
import re
import time
import csv
import ollama
import psutil
from config import TEST_DIR

# ===========================================================
# 설정
# ===========================================================
TARGET_MODEL = 'qwen2.5-coder'
RESULT_DIR = 'result_int'


def get_memory_usage():
    return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)


def evaluate_raw(code_content, ground_truth_cwes):
    """RAG / Tree-sitter 없이 순수 LLM만으로 CWE를 예측합니다."""

    prompt = f"""당신은 파이썬 보안 코드 분석 전문가입니다.
아래 [분석 대상 코드]의 취약점을 당신의 자체 지식만으로 분석하세요.

[핵심 지시사항]
1. 취약점이 없다고 판단되면 억지로 찾지 말고 취약점 없음으로 판단하세요.
2. 여러 취약점 중 코드에서 발생한 가장 '직접적인 원인' 하나를 최종 CWE로 선택하세요.
3. 당신의 답변은 반드시 아래의 [출력 템플릿] 형태를 100% 똑같이 따라서 작성해야 합니다. 다른 말은 덧붙이지 마세요.

[분석 대상 코드]
{code_content}

=========================================
[출력 템플릿] (이 양식을 복사해서 빈칸을 채우세요)

▶ 취약점 분석 및 원리:
(여기에 한국어로 코드의 문제점과 패치 원리 설명)

▶ 맞춤형 개선 코드:
```python
(여기에 기존 코드를 안전하게 수정한 전체 코드 작성)
```

▶ 최종 판단 CWE:
(여기에 <CWE>태그</CWE> 작성)

[자동 채점을 위한 추가 규칙 - 필수]
답변의 가장 마지막에는 반드시 당신이 판단한 최종 CWE 번호를 CWE-XXX 형태의 태그로 감싸서 단 하나만 출력하세요. (예: <CWE>CWE-798</CWE>)
취약점이 없다면 <CWE>None</CWE>을 출력하세요.
"""

    start_time = time.time()
    start_mem = get_memory_usage()

    try:
        response = ollama.chat(
            model=TARGET_MODEL,
            messages=[{'role': 'user', 'content': prompt}]
        )
        result_text = response['message']['content']
    except Exception as e:
        result_text = f"Error: {e}"

    inference_time = round(time.time() - start_time, 2)
    memory_used = round(get_memory_usage() - start_mem, 2)

    match = re.search(r'<CWE>(.*?)</CWE>', result_text, re.IGNORECASE | re.DOTALL)
    predicted_cwe = match.group(1).strip() if match else "UNKNOWN"

    eval_result = 'TP' if predicted_cwe in ground_truth_cwes else 'FP'

    raw_preview = result_text.replace('\n', ' ').strip()
    if len(raw_preview) > 100:
        raw_preview = raw_preview[:100] + "..."

    return {
        'prediction': predicted_cwe,
        'eval_result': eval_result,
        'inference_time': inference_time,
        'memory_used': memory_used,
        'raw_response': raw_preview,
    }


def main():
    print(f"=== 🚀 [{TARGET_MODEL}] 논문용 평가 시스템 (RAG 없음) ===")

    os.makedirs(RESULT_DIR, exist_ok=True)

    test_files = [f for f in os.listdir(TEST_DIR) if f.endswith('.py')]
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 파이썬 파일이 없습니다.")
        return

    model_stats = {'Correct': 0, 'Incorrect': 0, 'total_time': 0.0, 'logs': []}
    csv_data = []
    total_files = len(test_files)

    print(f"\n⏳ [{TARGET_MODEL}] 평가 진행 중... (총 {total_files}개 파일)\n")

    for idx, filename in enumerate(test_files, start=1):
        file_path = os.path.join(TEST_DIR, filename)
        progress = (idx / total_files) * 100
        print(f"  ▶ [{idx}/{total_files}] ({progress:.1f}%) '{filename}' 분석 중... ", end='', flush=True)

        matches = re.findall(r'CWE-\d{3,4}', filename, re.IGNORECASE)
        ground_truth_cwes = matches if matches else ["None"]

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
        except Exception as e:
            print(f"⚠️ 읽기 실패: {e}")
            continue

        result = evaluate_raw(code_content, ground_truth_cwes)

        gt_str = "/".join(ground_truth_cwes)
        match_ox = 'O' if result['eval_result'] == 'TP' else 'X'

        if match_ox == 'O':
            model_stats['Correct'] += 1
            print(f"✅ 정답 (판정: {match_ox} | 시간: {result['inference_time']}s | 메모리: {result['memory_used']}MB)")
        else:
            model_stats['Incorrect'] += 1
            print(f"❌ 오답 (판정: {match_ox} | 정답: {gt_str} 👉 예측: {result['prediction']} | 시간: {result['inference_time']}s | 메모리: {result['memory_used']}MB)")

        model_stats['total_time'] += result['inference_time']

        csv_data.append({
            'Model': TARGET_MODEL,
            'Filename': filename,
            'Ground_Truth': gt_str,
            'Prediction': result['prediction'],
            'Match': match_ox,
            'Time_s': result['inference_time'],
            'Memory_MB': result['memory_used'],
        })

        model_stats['logs'].append(
            f"📄 {filename} | 정답: {gt_str:<10} | 예측: {result['prediction']:<10} | "
            f"판정: {match_ox} | 시간: {result['inference_time']}s | 메모리: {result['memory_used']}MB"
        )

    now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    correct = model_stats['Correct']
    total = total_files
    accuracy = (correct / total * 100) if total > 0 else 0
    avg_time = round(model_stats['total_time'] / total, 2) if total > 0 else 0

    report_path = os.path.join(RESULT_DIR, f'Eval_{TARGET_MODEL}_raw_{now_str}.txt')
    with open(report_path, 'w', encoding='utf-8') as rf:
        rf.write("=" * 60 + "\n")
        rf.write(f"📊 [{TARGET_MODEL}] CWE 식별 정확도 평가 리포트 (RAG 없음)\n")
        rf.write(f"📁 총 평가 파일: {total}개 | 🕒 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        rf.write("=" * 60 + "\n\n")
        rf.write(f"| Accuracy: {accuracy:.1f}% | Correct: {correct} | Incorrect: {total - correct} | Avg Time: {avg_time}s |\n\n")
        rf.write("📝 상세 로그\n" + "-" * 60 + "\n")
        for log in model_stats['logs']:
            rf.write(log + "\n")

    csv_path = os.path.join(RESULT_DIR, f'Data_{TARGET_MODEL}_raw_{now_str}.csv')
    with open(csv_path, 'w', encoding='utf-8-sig', newline='') as cf:
        writer = csv.DictWriter(cf, fieldnames=['Model', 'Filename', 'Ground_Truth', 'Prediction', 'Match', 'Time_s', 'Memory_MB'])
        writer.writeheader()
        writer.writerows(csv_data)

    print(f"\n✅ 평가 완료! 요약 리포트: '{report_path}'")
    print(f"📊 논문용 CSV 데이터: '{csv_path}'")
    print(f"\n📈 최종 정확도: {accuracy:.1f}% ({correct}/{total}) | 평균 추론 시간: {avg_time}s")


if __name__ == "__main__":
    main()