import requests
import json

OLLAMA_URL = "http://localhost:11434/api/chat"

payload = {
    "model": "qwen3:8b",
    "messages": [
        {"role": "system", "content": "You are a cybersecurity SOC analyst. Respond concisely."},
        {"role": "user", "content": "Explain what ThreatFox is in two sentences."}
    ],
    "stream": False
}

resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
resp.raise_for_status()

data = resp.json()
print("\nAssistant:", data["message"]["content"].strip())
