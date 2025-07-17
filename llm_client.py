# llm_client.py
import requests
import datetime

OLLAMA_URL = "http://localhost:11434/api/chat"

def query_llm(prompt: str, system_msg="You are a SOC analyst. Answer concisely.") -> str:
    """
    Enhanced LLM query function with MCP support and time awareness
    """
    # Get current time context
    now = datetime.datetime.now()
    utc_now = datetime.datetime.utcnow()
    
    time_context = f"""
CURRENT TIME INFORMATION:
- Local Time: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}
- UTC Time: {utc_now.strftime('%Y-%m-%d %H:%M:%S UTC')}
- Day of Week: {now.strftime('%A')}
- Timezone: {now.astimezone().tzinfo}
"""
    
    # Enhanced system prompt with MCP guidelines
    enhanced_system_msg = f"""{system_msg}

{time_context}

MCP GUIDELINES:
- Provide structured, actionable responses
- Include severity levels (Critical, High, Medium, Low)
- Consider time-sensitive aspects of security events
- Reference relevant frameworks (MITRE ATT&CK, NIST) when applicable
- Base conclusions on available evidence
- Maintain awareness of current time for temporal analysis

Use the current time information above when analyzing events or making time-sensitive recommendations."""
    
    # Add time awareness to user prompt
    enhanced_prompt = f"""Current Analysis Request (Time: {now.strftime('%Y-%m-%d %H:%M:%S')}):

{prompt}

Please consider the current time context in your analysis."""
    
    payload = {
        "model": "qwen3:8b",
        "messages": [
            {"role": "system", "content": enhanced_system_msg},
            {"role": "user", "content": enhanced_prompt}
        ],
        "stream": False,
        "options": {
            "temperature": 0.1
        }
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=30)
        response.raise_for_status()
        return response.json()["message"]["content"].strip()
    except requests.exceptions.RequestException as e:
        return f"Error communicating with LLM: {str(e)}"
    except KeyError as e:
        return f"Unexpected response format: {str(e)}"