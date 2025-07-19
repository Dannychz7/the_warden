import requests
import datetime
import json
from typing import Any
from tools.intel_providers import query_abuseip, query_threatfox
from tools.tool_schema import tool_list
import re
import json
from typing import Optional, Dict, Any

OLLAMA_URL = "http://localhost:11434/api/chat"

ACTION_MAP = {
    "query_abuseip": query_abuseip,
    "query_threatfox": query_threatfox,
}

def execute_model_action(model_response: str) -> Any:
    try:
        action_data = json.loads(model_response)
        action = action_data.get("action")
        params = action_data.get("parameters", {})

        func = ACTION_MAP.get(action)
        if not func:
            return f"[!] Unknown action: '{action}'"
        return func(**params)
    except json.JSONDecodeError as e:
        return f"[!] Invalid JSON format from model: {e}"
    except Exception as e:
        return f"[!] Failed to execute action: {e}"

def parse_json_from_response(response: str) -> Optional[Dict[str, Any]]:
    """
    Extract the first valid JSON object from the LLM response string.
    Uses multiple strategies for robust parsing.
    Returns None if no valid JSON found.
    """
    
    # Strategy 1: Try to parse the entire response as JSON first
    try:
        parsed = json.loads(response.strip())
        if isinstance(parsed, dict) and "action" in parsed:
            return parsed
    except json.JSONDecodeError:
        pass
    
    # Strategy 2: Look for JSON code blocks (```json ... ```)
    code_block_pattern = re.compile(r'```(?:json)?\s*(\{.*?\})\s*```', re.DOTALL | re.IGNORECASE)
    code_block_match = code_block_pattern.search(response)
    if code_block_match:
        try:
            parsed = json.loads(code_block_match.group(1))
            if isinstance(parsed, dict) and "action" in parsed:
                return parsed
        except json.JSONDecodeError:
            pass
    
    # Strategy 3: Find JSON objects using balanced brace counting
    json_candidates = find_json_objects(response)
    
    for candidate in json_candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict) and "action" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue
    
    # Strategy 4: Fallback regex for simple cases
    fallback_pattern = re.compile(r'\{[^{}]*"action"[^{}]*\}')
    fallback_matches = fallback_pattern.findall(response)
    
    for match in fallback_matches:
        try:
            parsed = json.loads(match)
            if isinstance(parsed, dict) and "action" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue
    
    return None

def find_json_objects(text: str) -> list:
    """
    Find potential JSON objects in text using balanced brace counting.
    Returns a list of candidate JSON strings.
    """
    candidates = []
    
    for i, char in enumerate(text):
        if char == '{':
            # Found opening brace, try to find matching closing brace
            brace_count = 1
            in_string = False
            escape_next = False
            
            for j in range(i + 1, len(text)):
                current_char = text[j]
                
                if escape_next:
                    escape_next = False
                    continue
                    
                if current_char == '\\':
                    escape_next = True
                    continue
                    
                if current_char == '"' and not escape_next:
                    in_string = not in_string
                    continue
                    
                if not in_string:
                    if current_char == '{':
                        brace_count += 1
                    elif current_char == '}':
                        brace_count -= 1
                        
                        if brace_count == 0:
                            # Found complete JSON object
                            candidate = text[i:j+1]
                            candidates.append(candidate)
                            break
    
    return candidates

def build_system_message(system_msg: str, tool_list: list) -> str:
    now = datetime.datetime.now()
    utc_now = datetime.datetime.utcnow()
    time_context = f"""
CURRENT TIME INFORMATION:
- Local Time: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}
- UTC Time: {utc_now.strftime('%Y-%m-%d %H:%M:%S UTC')}
- Day of Week: {now.strftime('%A')}
- Timezone: {now.astimezone().tzinfo}
"""

    tool_list_json = json.dumps(tool_list, indent=2)

    return f"""{system_msg}

{time_context}

TOOL SCHEMA:
The following tools are available for use. Always respond using a JSON object with two fields: `action` and `parameters`.

Tool Definitions:
{tool_list_json}

RESPONSE FORMAT EXAMPLE:
{{
  "action": "query_abuseip",
  "parameters": {{
    "ip": "1.1.1.1"
  }}
}}

MCP GUIDELINES:
- Provide structured, actionable responses
- Include severity levels (Critical, High, Medium, Low)
- Reference relevant frameworks (MITRE ATT&CK, NIST) when applicable
- Be aware of and leverage current time for context
- Use available tools with accurate parameters and respond only in JSON format
"""

def query_llm(prompt: str, system_msg: str = "You are a SOC analyst. Answer concisely.") -> str:
    enhanced_system_msg = build_system_message(system_msg, tool_list)
    now = datetime.datetime.now()

    enhanced_prompt = f"""Current Analysis Request (Time: {now.strftime('%Y-%m-%d %H:%M:%S')}):

{prompt}

Please respond only with a JSON object specifying the tool to use and its parameters. Do not provide additional commentary.
"""

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
        return f"[!] Error communicating with LLM: {e}"
    except KeyError as e:
        return f"[!] Unexpected response format: missing key {e}"

def handle_input(prompt: str) -> str:
    print(f"[Core] Handling input: {prompt}")
    model_response = query_llm(prompt)

    parsed_action = parse_json_from_response(model_response)
    if not parsed_action:
        return (
            f"[MCP-LLM RAW RESPONSE]:\n{model_response}\n\n"
            "[ERROR]: Could not find valid JSON action in the model response."
        )

    # Serialize back to string for logging/debugging if you want
    json_for_logging = json.dumps(parsed_action, indent=2)
    print(f"[Core] Parsed JSON action:\n{json_for_logging}")

    result = execute_model_action(json.dumps(parsed_action))

    final_output = (
        f"[MCP-LLM THOUGHT + TOOL REQUEST]:\n{json_for_logging}\n\n"
        f"[TOOL OUTPUT]:\n{result}"
    )
    return final_output




