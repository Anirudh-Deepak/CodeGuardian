import time
import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise ValueError("GEMINI_API_KEY not found. Check your .env file.")

client = genai.Client(api_key=API_KEY)


def get_ai_advice(secret_type, code_line):

    prompt = f"""
You are a cybersecurity expert.

A security scanner detected a secret in code.

Secret Type: {secret_type}
Code Line: {code_line}

Respond STRICTLY in this format:

Why Dangerous:
<short explanation>

Fix:
<clear secure fix>

Rules:
- Keep it concise
- No markdown
- No extra headings
"""

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )
            return response.text

        except Exception as e:

            if "429" in str(e):
                time.sleep(3)
            else:
                return f"AI Error: {str(e)}"

    return "Rate limit exceeded"