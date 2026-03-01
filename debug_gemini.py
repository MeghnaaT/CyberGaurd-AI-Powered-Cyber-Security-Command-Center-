import os
import traceback
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("GEMINI_API_KEY")
print("KEY_PRESENT:", bool(key))

genai.configure(api_key=key)

try:
    m = genai.GenerativeModel("gemini-1.5-flash")
    r = m.generate_content("Say hello in one line.")
    print("OK:", getattr(r, "text", r))
except Exception as e:
    print("ERROR_TYPE:", type(e).__name__)
    traceback.print_exc()