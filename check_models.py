import google.generativeai as genai

genai.configure(api_key="AIzaSyA2D85YNmYaOcHPjowYCHeOAMxZRmcK9qo")

for m in genai.list_models():
    print(m.name, m.supported_generation_methods)