import os
import datetime
import re
import time
from google import genai
from dotenv import load_dotenv
from config import TEST_DIR
from rag_engine import RAGEngine

# 💡 1. 환경 변수 설정 및 최신형 Gemini 클라이언트 초기화
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("❌ 에러: .env 파일에 GEMINI_API_KEY가 없습니다!")
    exit()

client = genai.Client(api_key=GEMINI_API_KEY)

# 💡 2. 사용할 Gemini 모델 지정
TARGET_MODEL = 'gemini-2.5-pro'

def evaluate_with_gemini(code_content, rag_context, ground_truth_cwes):
    """Gemini API 전용 평가 함수"""
    
    # 💡 [핵심] 생각의 사슬(CoT)을 유도하고, 정답은 태그 안에 넣게 지시!
    prompt = f"""
    당신은 파이썬 보안 코드 분석기입니다.
    아래 제공된 코드를 분석하여 취약점을 찾아내세요.
    
    [응답 규칙]
    1. 코드를 1~2문장으로 자유롭게 분석하며 취약점을 파악하세요.
    2. 분석이 끝난 후, 답변의 **가장 마지막**에 반드시 아래 태그 형식으로 최종 취약점 번호 1개만 감싸서 출력하세요.
       형식: <CWE>CWE-XXX</CWE>
    
    [참고 지식(DB)]
    {rag_context if rag_context else "일치하는 보안 지식 없음"}
    
    [분석할 코드]
    {code_content}
    """
    
    start_time = time.time()
    
    try:
        # 💡 최신 SDK의 모델 호출 방식 적용
        response = client.models.generate_content(
            model=TARGET_MODEL,
            contents=prompt
        )
        result_text = response.text
    except Exception as e:
        result_text = f"Error: {e}"
        
    inference_time = round(time.time() - start_time, 2)
    
    # <CWE> 태그 안의 숫자만 쏙 뽑아내기
    match = re.search(r'<CWE>.*?(\d+).*?</CWE>', result_text, re.IGNORECASE | re.DOTALL)
    predicted_cwe = f"CWE-{match.group(1)}" if match else "UNKNOWN"
    
    if predicted_cwe in ground_truth_cwes:
        eval_result = f'TP (정답: {predicted_cwe} 일치)'
    else:
        eval_result = f'FP (오답 - GT:{ground_truth_cwes} vs Pred:{predicted_cwe})'
        
    raw_preview = result_text.replace('\n', ' ').strip()
    if len(raw_preview) > 100: raw_preview = raw_preview[:100] + "..."
        
    return {
        'prediction': predicted_cwe, 
        'eval_result': eval_result,
        'inference_time': inference_time,
        'raw_response': raw_preview
    }

def main():
    print(f"=== 🚀 [{TARGET_MODEL}] 전용 자동 평가 시스템 시작 ===")
    rag = RAGEngine()
    RESULT_DIR = 'result_integrated'
    
    if not os.path.exists(RESULT_DIR): os.makedirs(RESULT_DIR)

    test_files = [f for f in os.listdir(TEST_DIR) if f.endswith('.py')]
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 파이썬 파일이 없습니다.")
        return

    model_stats = {'Correct': 0, 'Incorrect': 0, 'total_time': 0, 'logs': []}
    total_files = len(test_files)
    
    print(f"\n⏳ [{TARGET_MODEL}] 모델 평가 진행 중... (총 {total_files}개 파일)")
    
    for idx, filename in enumerate(test_files, start=1):
        file_path = os.path.join(TEST_DIR, filename)
        
        progress = (idx / total_files) * 100
        print(f"  ▶ [{idx}/{total_files}] ({progress:.1f}%) '{filename}' 분석 중... ", end='', flush=True)
        
        matches = re.findall(r'\d{3,4}', filename)
        ground_truth_cwes = [f"CWE-{m}" for m in matches]
        
        if not ground_truth_cwes:
            print("⚠️ 무시됨 (CWE 번호 없음)")
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            code_content = f.read()
            
        rag_context = rag.get_context(code_content)
        
        result = evaluate_with_gemini(code_content, rag_context, ground_truth_cwes)
        
        if 'TP' in result['eval_result']:
            model_stats['Correct'] += 1
            print(f"✅ 정답 ({result['inference_time']}s)")
        else:
            model_stats['Incorrect'] += 1
            print(f"❌ 오답 ({result['inference_time']}s) -> AI실제답변: {result['raw_response']}")
            
        model_stats['total_time'] += result['inference_time']
        
        log_str = f"📄 {filename} | 정답: {ground_truth_cwes} | AI 예측: {result['prediction']} 👉 {result['eval_result']} | {result['inference_time']}s"
        model_stats['logs'].append(log_str)

    report_filename = os.path.join(RESULT_DIR, f'Eval_Gemini_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
    
    with open(report_filename, mode='w', encoding='utf-8') as rf:
        rf.write("=" * 60 + "\n")
        rf.write(f"📊 [{TARGET_MODEL}] CWE 식별 정확도(Accuracy) 평가 리포트\n")
        rf.write(f"📁 총 평가 파일: {len(test_files)}개 | 🕒 일시: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        rf.write("=" * 60 + "\n\n")
        
        rf.write("| Model Name | Accuracy | Correct | Incorrect | Avg Time/File |\n")
        rf.write("|---|---|---|---|---|\n")

        correct = model_stats['Correct']
        incorrect = model_stats['Incorrect']
        total = correct + incorrect
        
        accuracy = (correct / total * 100) if total > 0 else 0
        avg_time = round(model_stats['total_time'] / total, 2) if total > 0 else 0
        
        rf.write(f"| {TARGET_MODEL} | **{accuracy:.1f}%** | {correct} | {incorrect} | {avg_time}s |\n\n")

        rf.write("=" * 60 + "\n")
        rf.write("📝 개별 파일 분석 상세 로그\n")
        rf.write("=" * 60 + "\n\n")

        for log in model_stats['logs']:
            rf.write(log + "\n")

    print(f"\n✅ 평가 완료! 결과 리포트가 '{report_filename}'에 저장되었습니다.")

if __name__ == "__main__":
    main()