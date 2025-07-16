# llm_client.py
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"

def query_llm(prompt: str, system_msg="You are a SOC analyst. Answer concisely.") -> str:
    payload = {
        "model": "qwen3:8b",
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt}
        ],
        "stream": False
    }
    response = requests.post(OLLAMA_URL, json=payload)
    response.raise_for_status()
    return response.json()["message"]["content"].strip()
