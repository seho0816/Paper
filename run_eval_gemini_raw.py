import os
import datetime
import re
import time
import csv
from google import genai
from dotenv import load_dotenv
from config import TEST_DIR
from rag_engine import RAGEngine

# 1. 환경 변수 설정 및 최신형 Gemini 클라이언트 초기화
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("❌ 에러: .env 파일에 GEMINI_API_KEY가 없습니다!")
    exit()

client = genai.Client(api_key=GEMINI_API_KEY)

# 2. 사용할 Gemini 모델 지정
TARGET_MODEL = 'gemini-2.5-pro'


def evaluate_with_gemini(code_content, rag_context, ground_truth_cwes):
    """Gemini API 전용 평가 함수"""

    prompt = f"""당신은 파이썬 보안 코드 분석 전문가입니다.
아래 [참고 지식]을 바탕으로 [분석 대상 코드]의 취약점을 분석하세요.

[핵심 지시사항]
1. 복붙 금지: DB 예제 코드를 그대로 복사하지 마세요. 반드시 [분석 대상 코드]의 문맥을 유지하면서 패치하세요.
2. 무관함 판단: 참고 지식과 관련이 없으면 억지로 찾지 말고 취약점 없음으로 판단하세요.
3. 정확한 식별: 여러 취약점 중 코드에서 발생한 가장 '직접적인 원인' 하나를 최종 CWE로 선택하세요.
4. 양식 준수: 당신의 답변은 반드시 아래의 [출력 템플릿] 형태를 100% 똑같이 따라서 작성해야 합니다. 다른 말은 덧붙이지 마세요.

[참고 지식]
{rag_context if rag_context else "일치하는 보안 지식 없음"}

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

    try:
        response = client.models.generate_content(
            model=TARGET_MODEL,
            contents=prompt
        )
        result_text = response.text
    except Exception as e:
        result_text = f"Error: {e}"

    inference_time = round(time.time() - start_time, 2)

    # <CWE> 태그 안의 문구 뽑아내기
    match = re.search(r'<CWE>(.*?)</CWE>', result_text, re.IGNORECASE | re.DOTALL)
    predicted_cwe = match.group(1).strip() if match else "UNKNOWN"

    if predicted_cwe in ground_truth_cwes:
        eval_result = 'TP'  # 정답
    else:
        eval_result = 'FP'  # 오답

    raw_preview = result_text.replace('\n', ' ').strip()
    if len(raw_preview) > 100:
        raw_preview = raw_preview[:100] + "..."

    return {
        'prediction': predicted_cwe,
        'eval_result': eval_result,
        'inference_time': inference_time,
        'raw_response': raw_preview
    }


def main():
    print(f"=== 🚀 [{TARGET_MODEL}] 논문용 데이터 수집 평가 시스템 시작 ===")
    rag = RAGEngine()
    RESULT_DIR = 'result_int'

    if not os.path.exists(RESULT_DIR):
        os.makedirs(RESULT_DIR)

    test_files = [f for f in os.listdir(TEST_DIR) if f.endswith('.py')]
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 파이썬 파일이 없습니다.")
        return

    model_stats = {'Correct': 0, 'Incorrect': 0, 'total_time': 0, 'logs': []}
    csv_data = []

    total_files = len(test_files)
    print(f"\n⏳ [{TARGET_MODEL}] 모델 평가 진행 중... (총 {total_files}개 파일)")

    for idx, filename in enumerate(test_files, start=1):
        file_path = os.path.join(TEST_DIR, filename)

        progress = (idx / total_files) * 100
        print(f"  ▶ [{idx}/{total_files}] ({progress:.1f}%) '{filename}' 분석 중... ", end='', flush=True)

        # 파일명에서 정답 추출 (예: CWE-798_vuln.py -> CWE-798)
        matches = re.findall(r'CWE-\d{3,4}', filename, re.IGNORECASE)
        # 파일명에 CWE가 없으면 None이 정답(패치된 코드 등)
        ground_truth_cwes = matches if matches else ["None"]

        with open(file_path, 'r', encoding='utf-8') as f:
            code_content = f.read()

        rag_context = rag.get_context(code_content)
        result = evaluate_with_gemini(code_content, rag_context, ground_truth_cwes)

        gt_str = "/".join(ground_truth_cwes)
        match_ox = 'O' if result['eval_result'] == 'TP' else 'X'

        # 터미널 간략 출력
        if match_ox == 'O':
            model_stats['Correct'] += 1
            print(f"✅ 정답 (판정: {match_ox} | 시간: {result['inference_time']}s)")
        else:
            model_stats['Incorrect'] += 1
            print(f"❌ 오답 (판정: {match_ox} | 정답: {gt_str} 👉 예측: {result['prediction']} | 시간: {result['inference_time']}s)")

        model_stats['total_time'] += result['inference_time']

        # CSV에 들어갈 데이터
        csv_data.append({
            'Model': TARGET_MODEL,
            'Filename': filename,
            'Ground_Truth': gt_str,
            'Prediction': result['prediction'],
            'Match': match_ox,
            'Time_s': result['inference_time'],
            'Memory_MB': 'API'  # 제미나이는 클라우드 API라 로컬 메모리 사용량이 없음
        })

        # TXT 파일용 간략 로그
        log_str = f"📄 {filename} | 정답: {gt_str:<10} | 예측: {result['prediction']:<10} | 판정: {match_ox} | 시간: {result['inference_time']}s"
        model_stats['logs'].append(log_str)

    now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # 1. 텍스트 리포트 저장
    report_filename = os.path.join(RESULT_DIR, f'Eval_Gemini_{now_str}.txt')
    with open(report_filename, mode='w', encoding='utf-8') as rf:
        rf.write("=" * 60 + "\n")
        rf.write(f"📊 [{TARGET_MODEL}] CWE 식별 정확도 평가 리포트\n")
        rf.write("=" * 60 + "\n\n")
        correct = model_stats['Correct']
        total = total_files
        accuracy = (correct / total * 100) if total > 0 else 0
        avg_time = round(model_stats['total_time'] / total, 2) if total > 0 else 0
        rf.write(f"| Accuracy: {accuracy:.1f}% | Correct: {correct} | Incorrect: {total - correct} | Avg Time: {avg_time}s |\n\n")

        rf.write("📝 상세 로그\n")
        rf.write("-" * 60 + "\n")
        for log in model_stats['logs']:
            rf.write(log + "\n")

    # 2. 엑셀용 CSV 데이터 저장
    csv_filename = os.path.join(RESULT_DIR, f'Data_Gemini_{now_str}.csv')
    with open(csv_filename, mode='w', encoding='utf-8-sig', newline='') as cf:
        writer = csv.DictWriter(cf, fieldnames=['Model', 'Filename', 'Ground_Truth', 'Prediction', 'Match', 'Time_s', 'Memory_MB'])
        writer.writeheader()
        writer.writerows(csv_data)

    print(f"\n✅ 평가 완료! 요약 리포트: '{report_filename}'")
    print(f"📊 논문용 CSV 데이터가 '{csv_filename}'에 저장되었습니다! (엑셀에서 바로 열어보세요)")


if __name__ == "__main__":
    main()