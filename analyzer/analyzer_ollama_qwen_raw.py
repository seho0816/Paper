import os
import datetime
import ollama

print("=== 순수 LLM 보안 분석 (Qwen 2.5 Coder / No RAG) ===")

while True:
    print("\n[파일 경로 입력 대기 중...]")
    target_file = input("경로 (종료 'exit'): ").strip()
    if target_file.lower() == 'exit': break
    if not target_file or not os.path.exists(target_file): continue

    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            user_code = f.read()
    except Exception as e:
        print(f"⚠️ 파일 읽기 오류: {e}"); continue

    print(f"\n🧠 Qwen 2.5 Coder 정밀 분석 시작 (RAG 지식 없음)...")
    
    prompt = f"""당신은 파이썬 보안 코드 분석 전문가입니다.
    아래 [분석 대상 코드]의 취약점을 당신의 자체 지식만으로 분석하세요.

    [핵심 지시사항]
    1. 취약점이 없다고 판단되면 억지로 찾지 말고 취약점 없음으로 판단하세요.
    2. 여러 취약점 중 코드에서 발생한 가장 '직접적인 원인' 하나를 최종 CWE로 선택하세요.
    3. 당신의 답변은 반드시 아래의 [출력 템플릿] 형태를 100% 똑같이 따라서 작성해야 합니다. 다른 말은 덧붙이지 마세요.

    [분석 대상 코드]
    {user_code}

    =========================================
    [출력 템플릿] (이 양식을 복사해서 빈칸을 채우세요)

    ▶ 취약점 분석 및 원리:
    (여기에 한국어로 코드의 문제점과 패치 원리 설명)

    ▶ 맞춤형 개선 코드:
    ```python
    (여기에 기존 코드를 안전하게 수정한 전체 코드 작성)
    ```
    ▶ 최종 판단 CWE:
    (여기에 태그 작성)
    [자동 채점을 위한 추가 규칙 - 필수]
    답변의 가장 마지막에는 반드시 당신이 판단한 최종 CWE 번호를 CWE-XXX 형태의 태그로 감싸서 단 하나만 출력하세요. (예: CWE-798)
    취약점이 없다면 None을 출력하세요.
    """
    try:
        # 모델명을 qwen2.5-coder로 정확히 지정
        response = ollama.chat(model='qwen2.5-coder', messages=[{'role': 'user', 'content': prompt}])
        result_text = response['message']['content']
    except Exception as e:
        print(f"오류 발생 (Ollama 실행 확인): {e}")
        continue

    print("\n================ [AI 분석 결과] ================")
    print(result_text)
    print("================================================\n")
    
    os.makedirs("result", exist_ok=True)
    now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.basename(target_file).replace('.py', '')
    filename = os.path.join("result", f"result_ollama_qwen2.5_raw_{base_name}_{now}.txt")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"=== 순수 LLM(Qwen 2.5 Coder) 보안 분석 리포트 ({now}) ===\n")
        f.write(f"=== 분석 대상 파일: {target_file} ===\n\n")
        f.write(result_text)
    
    print(f"✅ 분석 결과가 '{filename}' 파일에 저장되었습니다!") 