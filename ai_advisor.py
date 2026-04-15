from google import genai
import time
client = genai.Client(api_key="AIzaSyA2D85YNmYaOcHPjowYCHeOAMxZRmcK9qo")
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