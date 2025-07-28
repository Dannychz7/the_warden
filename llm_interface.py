"""
llm_interface.py - Interface for communicating with Qwen3 via Ollama
"""
import json
import requests
import re
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

class LLMInterface:
    """Interface for Qwen3 LLM communication"""
    
    def __init__(self, ollama_url: str = "http://localhost:11434/api/chat", model: str = "qwen3:8b"):
        self.ollama_url = ollama_url
        self.model = model
        zulu_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # System message defining The Warden's persona and capabilities
        self.system_message = """You are The Warden, an expert SOC (Security Operations Center) analyst with years of cybersecurity experience. You have access to various threat intelligence tools and APIs.

Your role is to:
1. Analyze security threats and indicators of compromise (IoCs)
2. Make decisions about which tools to use for investigation
3. Provide clear, actionable security assessments
4. Think step-by-step through complex security scenarios

CURRENT ZULU TIME: {zulu_time}

AVAILABLE DECISION MODES:
- "use_tool": Execute a specific tool with arguments
- "complete": Finish analysis and provide final report

When deciding what to do next, respond with a JSON object containing:
{{
    "action": "use_tool" | "complete",
    "reasoning": "Brief explanation of why you're taking this action",
    "tool_name": "name_of_tool_to_use" (only if action is "use_tool"),
    "arguments": {{"arg1": "value1"}} (only if action is "use_tool")
}}

IMPORTANT: You may include thinking/reasoning in <think></think> tags before your JSON response, but the final response must contain a valid JSON object. The JSON should be the last part of your response.

Always think like a SOC analyst - be thorough, consider multiple threat vectors, and provide actionable intelligence.""".format(zulu_time=zulu_time)

    def _call_llm(self, messages: List[Dict[str, str]]) -> Optional[str]:
        """Make a call to the LLM via Ollama"""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.1
            }
        }

        try:
            response = requests.post(self.ollama_url, json=payload, timeout=300)
            response.raise_for_status()
            return response.json()["message"]["content"].strip()
        except requests.exceptions.RequestException as e:
            print(f"[LLM] Error communicating with LLM: {e}")
            return None
        except KeyError as e:
            print(f"[LLM] Unexpected response format: missing key {e}")
            return None
    
    def get_next_action(self, analysis_context: Dict[str, Any], available_tools: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
        """Ask Qwen3 what action to take next in the analysis"""
        
        # Build context for the LLM
        context_prompt = self._build_context_prompt(analysis_context, available_tools)
        
        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": context_prompt}
        ]
        
        response = self._call_llm(messages)
        if not response:
            return None
        
        # Try to parse JSON response, handling <think> tags and other text
        try:
            # First, try to remove <think> tags if they exist
            cleaned_response = response
            if '<think>' in response and '</think>' in response:
                # Remove everything between <think> and </think> tags
                cleaned_response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
            
            # Find JSON boundaries more robustly
            json_start = cleaned_response.find('{')
            if json_start == -1:
                # Try the original response if cleaning didn't help
                json_start = response.find('{')
                cleaned_response = response
            
            json_end = cleaned_response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = cleaned_response[json_start:json_end]
                
                # Additional cleanup: remove any trailing text after the JSON
                # Count braces to find the actual end of the JSON object
                brace_count = 0
                actual_end = json_start
                for i in range(json_start, len(cleaned_response)):
                    if cleaned_response[i] == '{':
                        brace_count += 1
                    elif cleaned_response[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            actual_end = i + 1
                            break
                
                json_str = cleaned_response[json_start:actual_end]
                
                # Parse and validate the JSON
                parsed_json = json.loads(json_str)
                
                # Validate required fields
                if 'action' not in parsed_json:
                    print(f"[LLM] Missing 'action' field in response")
                    return None
                    
                return parsed_json
                
            else:
                print(f"[LLM] No valid JSON found in response: {response}")
                return None
                
        except json.JSONDecodeError as e:
            print(f"[LLM] Failed to parse JSON response: {e}")
            print(f"[LLM] Raw response: {response}")
            
            # Try one more fallback - look for JSON-like patterns
            try:
                # Look for patterns like {"action": "...", ...}
                json_pattern = r'\{[^{}]*"action"[^{}]*\}'
                matches = re.findall(json_pattern, response, re.DOTALL)
                if matches:
                    # Try the first match
                    fallback_json = json.loads(matches[0])
                    print(f"[LLM] Recovered using fallback pattern matching")
                    return fallback_json
            except:
                pass
                
            return None
        except Exception as e:
            print(f"[LLM] Unexpected error parsing response: {e}")
            return None
    
    def _build_context_prompt(self, analysis_context: Dict[str, Any], available_tools: List[Dict[str, str]]) -> str:
        """Build the context prompt for the LLM"""
        prompt = f"""ANALYSIS SESSION CONTEXT:

USER QUERY: {analysis_context['user_query']}
CURRENT ITERATION: {analysis_context['iteration']}
MAX ITERATIONS: 5

AVAILABLE TOOLS:"""
        
        for tool in available_tools:
            prompt += f"\n- {tool['name']}: {tool.get('description', 'No description')}"
            if 'server' in tool:
                prompt += f" (via {tool['server']})"
        
        if analysis_context['tool_results']:
            prompt += "\n\nPREVIOUS TOOL RESULTS:"
            for result in analysis_context['tool_results']:
                prompt += f"\n\nTool: {result['tool']}"
                prompt += f"\nArguments: {json.dumps(result['arguments'])}"
                prompt += f"\nResult: {json.dumps(result['result'])[:500]}..."  # Truncate long results
        
        prompt += """

As The Warden, what should I do next? Consider:
1. Have I gathered enough information to make an assessment?
2. Are there other tools I should use for a complete analysis?
3. What would a thorough SOC analyst do in this situation?

Respond with a JSON decision object."""
        
        return prompt
    
    def generate_final_analysis(self, analysis_context: Dict[str, Any]) -> str:
        """Generate the final analysis report"""
        
        prompt = f"""FINAL ANALYSIS REQUEST:

USER QUERY: {analysis_context['user_query']}

INVESTIGATION RESULTS:"""
        
        if analysis_context['tool_results']:
            for i, result in enumerate(analysis_context['tool_results'], 1):
                prompt += f"\n\n{i}. Tool: {result['tool']}"
                prompt += f"\n   Arguments: {json.dumps(result['arguments'])}"
                prompt += f"\n   Result: {json.dumps(result['result'])}"
        else:
            prompt += "\n\nNo tools were executed during this analysis."
        
        prompt += f"""

As The Warden, provide a comprehensive SOC analyst report including:
1. Executive Summary
2. Key Findings
3. Threat Assessment (High/Medium/Low)
4. Recommended Actions
5. Technical Details
6. Provide intel Sources
7. End report with:
    " ---
      **End of Report**
      **Generated by The Warden | Autonomous SOC Analyst **
    "

Format your response as a professional security report."""
        
        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": prompt}
        ]
        
        response = self._call_llm(messages)
        return response if response else "Failed to generate analysis report."