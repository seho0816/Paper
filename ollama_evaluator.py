import time
import os
import psutil
import ollama
import re

def get_memory_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

def evaluate(model_name, code_content, rag_context, ground_truth_cwes):
    prompt = f"""
    You are a professional Python Security Code Analyzer. 
    Analyze the [Source Code] based on the [Security Knowledge Base] to identify the most critical vulnerability.

    [Critical Instructions (Instruction Following)]
    1. **Strict Hallucination Control:** If the [Security Knowledge Base] is empty or clearly irrelevant to the code, you MUST respond ONLY with: "현재 보안 DB에 일치하는 취약점 패턴이 없어 정확한 분석을 수행할 수 없습니다."
    2. **Python-Specific Verification:** Prioritize the 'Python Note' in the knowledge base (e.g., random vs secrets, Flask-CORS misconfigurations).
    3. **Logical over Physical (Anti-Bias):** Prioritize identifying core logic flaws (CWE-285, 287) over simple resource limits (CWE-770, 400).
    4. **Context-Aware Patching:** Do not simply copy the DB example. Provide a brief explanation of how to patch the vulnerability within the original code's context.

    [Output Rules (In Korean)]
    1. **분석 결과 (Reasoning):** 취약점이 발견된 구체적인 코드 위치와 취약점의 원인, 그리고 패치 원리를 2~3문장 내외의 한국어로 설명하세요.
    2. **최종 태그:** 답변의 **가장 마지막**에 반드시 아래 태그 형식으로 식별된 CWE 번호 1개만 출력하세요.
       형식: <CWE>CWE-XXX</CWE>

    [참고 지식(Security Knowledge Base)]
    {rag_context if rag_context else "No relevant knowledge found."}

    [분석할 코드(Source Code)]
    {code_content}
    """
    
    start_time = time.time()
    start_mem = get_memory_usage()
    
    try:
        response = ollama.chat(model=model_name, messages=[{'role': 'user', 'content': prompt}])
        result_text = response['message']['content']
    except Exception as e:
        result_text = f"Error: {e}"
        
    inference_time = round(time.time() - start_time, 2)
    memory_used = round(get_memory_usage() - start_mem, 2)
    
    # 💡 <CWE> 태그 안의 숫자만 추출하여 정확도 극대화
    match = re.search(r'<CWE>.*?(\d+).*?</CWE>', result_text, re.IGNORECASE | re.DOTALL)
    predicted_cwe = f"CWE-{match.group(1)}" if match else "UNKNOWN"
    
    if predicted_cwe in ground_truth_cwes:
        eval_result = f'TP (정답: {predicted_cwe} 일치)'
    else:
        eval_result = f'FP (오답 - GT:{ground_truth_cwes} vs Pred:{predicted_cwe})'
        
    # 터미널 가독성을 위한 원본 답변 요약
    raw_preview = result_text.replace('\n', ' ').strip()
    if len(raw_preview) > 80: raw_preview = raw_preview[:80] + "..."
        
    return {
        'prediction': predicted_cwe, 
        'eval_result': eval_result,
        'inference_time': inference_time,
        'memory_used': memory_used,
        'raw_response': raw_preview
    }