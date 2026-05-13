import time
import os
import psutil
import ollama
import re

def get_memory_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

def evaluate(model_name, code_content, rag_context, ground_truth_cwes):
    # 💡 친구의 디테일한 프롬프트 + 나의 자동 채점 태그 지시
    prompt = f"""
        당신은 파이썬 보안 전문가입니vi다. 
        사용자가 입력한 코드 전체를 분석하세요.
        
        Hallucination 방지
        1. 제공된 [참고 지식(DB)]들을 복합적으로 참조하여 분석하세요.
        2. [참고 지식(DB)]이 비어있거나 무관하다면 "현재 보안 DB에 일치하는 취약점 패턴이 없어 정확한 분석을 수행할 수 없습니다." 라고만 답변하세요.
        3. 취약점이 발견되더라도, DB에 있는 해결책 예제 코드를 그대로 복사하지 마세요.
        4. 반드시 [사용자 입력 전체 코드]의 문맥을 유지하면서, 취약점만 안전하게 패치한 '사용자 맞춤형 개선 코드'를 작성하세요. 개선 코드는 함수명을 변경하지 마세요.
        5. 수정된 코드와 함께 관련 CWE 번호 및 패치 원리를 설명하세요.
        6. 사용자 입력 코드에서 취약점이 발견된 코드는 개별 항목을 만들어서 취약 코드를 똑같이 적어주세요.

        [지식 사용 규칙]
        1. MITRE 공식 CWE 기준은 CWE 번호, 공식명, 상위/관련 CWE, 최종 CWE 판단 기준을 보강하는 데 사용하세요.
        2. Python 취약/개선 예시 DB는 Python 코드 패턴 탐지와 사용자 맞춤형 개선 코드 작성에 사용하세요.
        3. MITRE 공식 기준 정보가 없는 후보 CWE라도, Python 취약/개선 예시 DB가 사용자 코드와 명확히 일치하면 분석을 중단하지 말고 기존 DB를 기준으로 분석하세요.
        4. MITRE 공식 기준은 보조 기준이며, 사용자 코드와 직접 관련 없는 MITRE 항목을 최종 CWE로 단정하지 마세요.

        [CWE 분류 우선순위 규칙]
        1. 참고 지식에 여러 CWE가 포함되어 있을 경우, 사용자 코드와 가장 직접적으로 일치하는 참고 지식의 CWE를 우선 후보로 삼으세요.

        2. 후보 CWE들 사이에 부모-자식 또는 상위-하위 관계가 있는 경우, 하위 CWE를 무조건 우선하지 마세요. 
        사용자 코드의 핵심 원인이 하위 CWE의 정의와 명확히 일치할 때만 하위 CWE를 최종 CWE로 선택하세요.

        3. 코드가 특정 참고 지식 또는 레슨 문서의 취약 코드 패턴과 매우 직접적으로 일치하고, 그 문서의 CWE가 상위 CWE라면 해당 상위 CWE를 최종 CWE로 유지할 수 있습니다. 
        이 경우 더 구체적인 하위 CWE는 "관련 CWE" 또는 "세부 후보 CWE"로만 언급하세요.

        4. 최종 CWE는 다음 기준을 순서대로 고려하여 선택하세요.
        - 사용자 코드와 가장 유사하게 검색된 참고 지식의 CWE
        - 코드에서 실제로 발생한 직접 원인
        - 공격자가 조작할 수 있는 입력값, 요청값, 파일, 파라미터 또는 외부 데이터
        - 검증, 제한, 인가, 인증, 예외 처리, 경계값 검사, 길이 제한, 크기 제한, 횟수 제한, 시간 제한 등의 보안 통제 부재 여부
        - 후보 CWE 중 사용자 코드의 취약 패턴을 가장 구체적으로 설명하는 CWE
        - 참고 지식에 명시된 CWE 관계 또는 취약점 설명과의 일치도

        5. 하위 CWE가 존재한다는 이유만으로 최종 CWE를 하위 CWE로 선택하지 마세요. 
        하위 CWE를 선택하려면 사용자 코드의 취약한 동작, 취약 원인, 공격 시나리오가 해당 하위 CWE의 설명과 명확하게 맞아야 합니다.

        6. 상위 CWE는 취약점의 넓은 범주나 결과를 설명할 때 "관련 CWE" 또는 "상위 CWE"로 언급할 수 있습니다. 
        단, 사용자 코드가 특정 하위 CWE보다 상위 CWE의 레슨/패턴과 더 직접적으로 일치한다면 상위 CWE를 최종 CWE로 선택할 수 있습니다.

        7. 보안 개선책에 특정 통제 방법이 포함된다는 이유만으로 최종 CWE를 변경하지 마세요. 
        최종 CWE는 "어떤 방식으로 고쳤는가"가 아니라 "사용자 코드에서 어떤 취약 원인이 실제로 발생했는가"를 기준으로 선택해야 합니다.

        8. 하나의 코드에서 여러 취약점이 독립적으로 존재하는 경우, 하나의 최종 CWE로 억지로 합치지 말고 취약점 항목별로 각각의 최종 CWE와 관련 CWE를 분리해서 작성하세요.

        9. 참고 지식과 사용자 코드가 부분적으로만 일치하는 경우, 확실한 취약점만 보고하세요. 
        근거가 부족한 CWE는 최종 CWE로 단정하지 말고 "가능성 있음", "관련 후보" 수준으로만 언급하세요.

        10. 최종 출력에는 반드시 다음을 분리해서 작성하세요.
        - 최종 CWE
        - 관련 CWE 또는 상위/하위 후보 CWE
        - 최종 CWE로 판단한 이유
        - 관련 CWE를 최종 CWE로 선택하지 않은 이유

        [자동 채점을 위한 추가 규칙]
        마지막으로, 당신이 판단한 최종 CWE 번호를 반드시 <CWE>CWE-XXX</CWE> 형태의 태그로 감싸서 답변 맨 마지막에 단 하나만 출력하세요. (예: <CWE>CWE-798</CWE>) 
        취약점이 없다면 <CWE>None</CWE>을 출력하세요.

        [참고 지식(Security Knowledge Base)]
        {rag_context}

        [분석할 코드(Source Code)]
        {code_content}
    """
    
    start_time = time.time()
    start_mem = get_memory_usage()
    
    try:
        # 질문자님의 훌륭한 Chat API 로직 유지
        response = ollama.chat(model=model_name, messages=[{'role': 'user', 'content': prompt}])
        result_text = response['message']['content']
    except Exception as e:
        result_text = f"Error: {e}"
        
    inference_time = round(time.time() - start_time, 2)
    memory_used = round(get_memory_usage() - start_mem, 2)
    
    # 💡 질문자님의 정교한 정규식 로직 유지 (숫자만 추출)
    match = re.search(r'<CWE>.*?(\d+).*?</CWE>', result_text, re.IGNORECASE | re.DOTALL)
    predicted_cwe = f"CWE-{match.group(1)}" if match else "UNKNOWN"
    
    if predicted_cwe in ground_truth_cwes:
        eval_result = f'TP (정답: {predicted_cwe} 일치)'
    else:
        eval_result = f'FP (오답 - GT:{ground_truth_cwes} vs Pred:{predicted_cwe})'
        
    # 터미널 가독성을 위한 원본 답변 요약 유지
    raw_preview = result_text.replace('\n', ' ').strip()
    if len(raw_preview) > 80: raw_preview = raw_preview[:80] + "..."
        
    return {
        'prediction': predicted_cwe, 
        'eval_result': eval_result,
        'inference_time': inference_time,
        'memory_used': memory_used,
        'raw_response': raw_preview
    }