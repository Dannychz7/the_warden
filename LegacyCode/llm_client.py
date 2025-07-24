import requests
import datetime
import json
from typing import Any, Dict, List, Optional, Tuple
from tools.intel_providers import query_abuseip, query_threatfox
from tools.tool_schema import tool_list
import re
import socket

OLLAMA_URL = "http://localhost:11434/api/chat"
MAX_ITERATIONS = 10  # Prevent infinite loops

ACTION_MAP = {
    "query_abuseip": query_abuseip,
    "query_threatfox": query_threatfox,
}

class AnalysisState:
    """Tracks the state of an ongoing analysis session"""
    def __init__(self, initial_prompt: str):
        self.initial_prompt = initial_prompt
        self.iteration_count = 0
        self.investigation_log = []
        self.findings = []
        self.completed = False
        self.confidence_level = "Low"
        
    def add_iteration(self, action: str, result: str, analysis: str):
        """Add an iteration to the investigation log"""
        self.iteration_count += 1
        self.investigation_log.append({
            "iteration": self.iteration_count,
            "timestamp": datetime.datetime.now().isoformat(),
            "action": action,
            "result": result,
            "analysis": analysis
        })
    
    def add_finding(self, finding: str, severity: str = "Medium"):
        """Add a security finding"""
        self.findings.append({
            "finding": finding,
            "severity": severity,
            "timestamp": datetime.datetime.now().isoformat()
        })

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
        if isinstance(parsed, dict) and ("action" in parsed or "analysis" in parsed):
            return parsed
    except json.JSONDecodeError:
        pass
    
    # Strategy 2: Look for JSON code blocks (```json ... ```)
    code_block_pattern = re.compile(r'```(?:json)?\s*(\{.*?\})\s*```', re.DOTALL | re.IGNORECASE)
    code_block_match = code_block_pattern.search(response)
    if code_block_match:
        try:
            parsed = json.loads(code_block_match.group(1))
            if isinstance(parsed, dict) and ("action" in parsed or "analysis" in parsed):
                return parsed
        except json.JSONDecodeError:
            pass
    
    # Strategy 3: Find JSON objects using balanced brace counting
    json_candidates = find_json_objects(response)
    
    for candidate in json_candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict) and ("action" in parsed or "analysis" in parsed):
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
                            candidate = text[i:j+1]
                            candidates.append(candidate)
                            break
    
    return candidates

def build_system_message(system_msg: str, tool_list: list, phase: str = "action") -> str:
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

    if phase == "action":
        response_format = """
RESPONSE FORMAT FOR TOOL EXECUTION:
{
  "action": "query_abuseip",
  "parameters": {
    "ip": "1.1.1.1"
  }
}
"""
    else:  # analysis phase
        response_format = """
RESPONSE FORMAT FOR ANALYSIS:
{
  "analysis": "Brief analysis of the tool output",
  "findings": ["List of security findings or IOCs discovered"],
  "next_action": "query_threatfox" or "complete" or specific tool name,
  "next_parameters": {"param": "value"} or null,
  "confidence": "High|Medium|Low",
  "reasoning": "Why this next action or completion decision was made"
}
"""

    base_instructions = f"""{system_msg}

{time_context}

TOOL SCHEMA:
The following tools are available for use:

Tool Definitions:
{tool_list_json}

{response_format}

ANALYSIS GUIDELINES:
- Provide structured, actionable responses
- Include severity levels (Critical, High, Medium, Low) 
- Reference relevant frameworks (MITRE ATT&CK, NIST) when applicable
- Be thorough but efficient in your investigation
- Mark investigation as "complete" when sufficient information has been gathered
- Focus on actionable intelligence and clear findings
"""

    return base_instructions

def query_llm_for_action(prompt: str, state: AnalysisState, system_msg: str = "You are a SOC analyst. Determine the next investigative action.") -> str:
    """Query LLM to determine next action to take"""
    enhanced_system_msg = build_system_message(system_msg, tool_list, "action")
    now = datetime.datetime.now()

    # Build context from previous iterations
    context = ""
    if state.investigation_log:
        context = "\nPREVIOUS INVESTIGATION STEPS:\n"
        for log_entry in state.investigation_log[-3:]:  # Last 3 iterations for context
            context += f"- Iteration {log_entry['iteration']}: {log_entry['action']} -> {log_entry['analysis'][:200]}...\n"

    enhanced_prompt = f"""Current Analysis Request (Time: {now.strftime('%Y-%m-%d %H:%M:%S')}):

INITIAL REQUEST: {state.initial_prompt}

CURRENT ITERATION: {state.iteration_count + 1}/{MAX_ITERATIONS}

{context}

CURRENT TASK: {prompt}

Please respond with a JSON object specifying the next tool to use and its parameters. Consider what information you still need to complete a thorough security analysis.
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

def query_llm_for_analysis(tool_output: str, state: AnalysisState, system_msg: str = "You are a SOC analyst. Analyze the tool output and determine next steps.") -> str:
    """Query LLM to analyze tool output and determine next steps"""
    enhanced_system_msg = build_system_message(system_msg, tool_list, "analysis")
    now = datetime.datetime.now()

    # Build context from previous findings
    context = ""
    if state.findings:
        context = "\nCURRENT FINDINGS:\n"
        for finding in state.findings:
            context += f"- [{finding['severity']}] {finding['finding']}\n"

    enhanced_prompt = f"""Analysis Request (Time: {now.strftime('%Y-%m-%d %H:%M:%S')}):

INITIAL REQUEST: {state.initial_prompt}
ITERATION: {state.iteration_count}/{MAX_ITERATIONS}

{context}

LATEST TOOL OUTPUT TO ANALYZE:
{tool_output}

Please analyze this output and determine:
1. What security-relevant information was discovered
2. What additional investigation steps are needed
3. Whether the investigation can be marked as complete

Respond with a JSON object containing your analysis and next steps.
"""

    payload = {
        "model": "qwen3:8b",
        "messages": [
            {"role": "system", "content": enhanced_system_msg},
            {"role": "user", "content": enhanced_prompt}
        ],
        "stream": False,
        "options": {
            "temperature": 0.2
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

def autonomous_investigation(initial_prompt: str) -> str:
    """
    Conduct an autonomous security investigation with iterative analysis
    """
    print(f"[Core] Starting autonomous investigation: {initial_prompt}")
    
    state = AnalysisState(initial_prompt)
    current_prompt = initial_prompt
    
    final_report = f"AUTONOMOUS SOC ANALYSIS REPORT\n{'='*50}\n"
    final_report += f"Initial Request: {initial_prompt}\n"
    final_report += f"Investigation Started: {datetime.datetime.now().isoformat()}\n\n"
    
    while state.iteration_count < MAX_ITERATIONS and not state.completed:
        print(f"[Core] Starting iteration {state.iteration_count + 1}")
        
        # Step 1: Get next action from LLM
        action_response = query_llm_for_action(current_prompt, state)
        parsed_action = parse_json_from_response(action_response)
        
        if not parsed_action or "action" not in parsed_action:
            final_report += f"\n[ERROR] Iteration {state.iteration_count + 1}: Could not parse action from LLM response\n"
            break
            
        # Step 2: Execute the action
        print(f"[Core] Executing action: {parsed_action.get('action')}")
        action_json = json.dumps(parsed_action)
        tool_result = execute_model_action(action_json)
        
        # Step 3: Get analysis of the results
        analysis_response = query_llm_for_analysis(str(tool_result), state)
        parsed_analysis = parse_json_from_response(analysis_response)
        
        if not parsed_analysis:
            analysis_summary = "Could not parse analysis response"
            next_action = "complete"  # Default to completion if analysis fails
        else:
            analysis_summary = parsed_analysis.get("analysis", "No analysis provided")
            
            # Extract findings
            findings = parsed_analysis.get("findings", [])
            for finding in findings:
                severity = "Medium"  # Default severity
                if isinstance(finding, dict):
                    severity = finding.get("severity", "Medium")
                    finding_text = finding.get("finding", str(finding))
                else:
                    finding_text = str(finding)
                state.add_finding(finding_text, severity)
            
            # Determine next action
            next_action = parsed_analysis.get("next_action", "complete")
            state.confidence_level = parsed_analysis.get("confidence", "Medium")
        
        # Add iteration to log
        state.add_iteration(
            action=parsed_action.get("action"),
            result=str(tool_result)[:500] + "..." if len(str(tool_result)) > 500 else str(tool_result),
            analysis=analysis_summary
        )
        
        # Add to report
        final_report += f"\n--- ITERATION {state.iteration_count} ---\n"
        final_report += f"Action: {parsed_action.get('action')}\n"
        final_report += f"Parameters: {json.dumps(parsed_action.get('parameters', {}), indent=2)}\n"
        final_report += f"Tool Output: {str(tool_result)[:300]}{'...' if len(str(tool_result)) > 300 else ''}\n"
        final_report += f"Analysis: {analysis_summary}\n"
        
        # Check completion conditions
        if (next_action == "complete" or 
            state.iteration_count >= MAX_ITERATIONS or
            "complete" in analysis_summary.lower()):
            state.completed = True
            print(f"[Core] Investigation completed after {state.iteration_count} iterations")
            break
            
        # Prepare next iteration
        if parsed_analysis and "next_parameters" in parsed_analysis:
            current_prompt = f"Continue investigation with {next_action}: {parsed_analysis.get('reasoning', '')}"
        else:
            current_prompt = f"Continue investigation based on previous findings"
    
    # Generate final summary
    final_report += f"\n{'='*50}\n"
    final_report += f"INVESTIGATION SUMMARY\n"
    final_report += f"Total Iterations: {state.iteration_count}\n"
    final_report += f"Confidence Level: {state.confidence_level}\n"
    final_report += f"Investigation Status: {'Completed' if state.completed else 'Max iterations reached'}\n\n"
    
    if state.findings:
        final_report += "SECURITY FINDINGS:\n"
        for i, finding in enumerate(state.findings, 1):
            final_report += f"{i}. [{finding['severity']}] {finding['finding']}\n"
    else:
        final_report += "No specific security findings identified.\n"
    
    final_report += f"\nInvestigation completed at: {datetime.datetime.now().isoformat()}\n"
    
    return final_report

def handle_input(prompt: str) -> str:
    """
    Enhanced input handler with autonomous investigation capability
    """
    # Check if this should trigger autonomous mode
    autonomous_keywords = ["investigate", "analyze", "full analysis", "autonomous", "deep dive"]
    should_go_autonomous = any(keyword in prompt.lower() for keyword in autonomous_keywords)
    
    if should_go_autonomous or len(prompt.split()) > 10:  # Complex queries get autonomous treatment
        return autonomous_investigation(prompt)
    else:
        # Simple single-shot analysis for basic queries
        print(f"[Core] Handling simple query: {prompt}")
        state = AnalysisState(prompt)
        
        model_response = query_llm_for_action(prompt, state)
        parsed_action = parse_json_from_response(model_response)
        
        if not parsed_action or "action" not in parsed_action:
            return (
                f"[MCP-LLM RAW RESPONSE]:\n{model_response}\n\n"
                "[ERROR]: Could not find valid JSON action in the model response."
            )

        json_for_logging = json.dumps(parsed_action, indent=2)
        print(f"[Core] Parsed JSON action:\n{json_for_logging}")

        result = execute_model_action(json.dumps(parsed_action))

        final_output = (
            f"[MCP-LLM THOUGHT + TOOL REQUEST]:\n{json_for_logging}\n\n"
            f"[TOOL OUTPUT]:\n{result}"
        )
        return final_output




