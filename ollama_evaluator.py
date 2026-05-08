import time
import os
import psutil
import ollama
import re

def get_memory_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

def evaluate(model_name, code_content, rag_context, ground_truth_cwes):
    # 💡 [핵심] 생각의 사슬(CoT)을 유도하고, 정답은 특정 태그로 추출하게 변경!
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
    start_mem = get_memory_usage()
    
    try:
        response = ollama.chat(model=model_name, messages=[{'role': 'user', 'content': prompt}])
        result_text = response['message']['content']
            
    except Exception as e:
        result_text = f"Error: {e}"
        
    inference_time = round(time.time() - start_time, 2)
    memory_used = round(get_memory_usage() - start_mem, 2)
    if memory_used < 0: memory_used = 0.0
    
    # 💡 [핵심] 이제 전체 텍스트에서 찾는 게 아니라, <CWE> 태그 안에 있는 숫자만 정확하게 빼옵니다!
    match = re.search(r'<CWE>.*?(\d+).*?</CWE>', result_text, re.IGNORECASE | re.DOTALL)
    predicted_cwe = f"CWE-{match.group(1)}" if match else "UNKNOWN"
    
    if predicted_cwe in ground_truth_cwes:
        eval_result = f'TP (정답: {predicted_cwe} 일치)'
    else:
        eval_result = f'FP (오답 - GT:{ground_truth_cwes} vs Pred:{predicted_cwe})'
        
    # 터미널 창 가독성을 위해 원본 텍스트의 줄바꿈을 없애고 100자만 자름
    raw_preview = result_text.replace('\n', ' ').strip()
    if len(raw_preview) > 100: raw_preview = raw_preview[:100] + "..."
        
    return {
        'prediction': predicted_cwe, 
        'eval_result': eval_result,
        'inference_time': inference_time,
        'memory_used': memory_used,
        'raw_response': raw_preview
    }