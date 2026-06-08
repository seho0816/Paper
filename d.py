
from google import genai
from dotenv import load_dotenv
import os
load_dotenv()
c = genai.Client(api_key=os.getenv('GEMINI_API_KEY'))
r = c.models.generate_content(model='gemini-2.5-pro', contents='hello')
print('응답:', r.text[:50] if r.text else 'None')