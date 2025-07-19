# mpd_server.py
import requests
import json
import re
from tools import get_apple_exec_info, get_apple_stock_price, get_apple_historical_price, get_random_noise
from tools.tool_schema import tool_list

OLLAMA_URL = "http://localhost:11434/api/chat"

# Tool registry for direct calling
tool_registry = {
    "get_apple_exec_info": get_apple_exec_info,
    "get_apple_stock_price": get_apple_stock_price,
    "get_apple_historical_price": get_apple_historical_price,
    "get_random_noise": get_random_noise,
}

def call_llm(messages):
    payload = {
        "model": "qwen3:8b",
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.1
        }
    }
    
    response = requests.post(OLLAMA_URL, json=payload)
    response.raise_for_status()
    return response.json()["message"]["content"]

def parse_tool_calls(content):
    """Parse all JSON tool calls from LLM response"""
    tool_calls = []
    try:
        # Look for all JSON objects in the response
        json_matches = re.findall(r'\{[^}]*"tool"[^}]*\}', content, re.DOTALL)
        for json_match in json_matches:
            try:
                tool_call = json.loads(json_match)
                if "tool" in tool_call:
                    tool_calls.append(tool_call)
            except json.JSONDecodeError:
                continue
    except Exception:
        pass
    return tool_calls

def is_final_answer(content):
    """Check if the response is a final answer"""
    # If it contains tool call JSON, it's definitely not final
    if parse_tool_calls(content):
        return False
    
    # Only consider it final if it explicitly starts with the final answer marker
    if content.strip().startswith("✅ Final Answer:"):
        return True
    
    return False

def main():
    user_input = "What can you tell me about Apple?"
    
    tools_available = "\n".join([
        f"{tool['name']}: {tool['description']}" for tool in tool_list
    ])
    
    system_prompt = (
        "You are a helpful assistant that can use tools to gather information.\n"
        "Follow this workflow:\n"
        "1. When you need information, call relevant tools using JSON format:\n"
        "   - You can only call one tool per response\n"
        "   - Use this format: {'tool': 'tool_name', 'input': {}}\n"
        "2. When you receive tool results, analyze them and decide:\n"
        "   - Call additional tools if you need more comprehensive information\n"
        "   - Provide a final answer if you have enough information\n"
        "3. For your final answer, start with '✅ Final Answer:' and provide a complete response\n"
        "\nFor questions about Apple, consider gathering:\n"
        "- Executive information (CEO, revenue, employees)\n"
        "- Current stock price\n"
        "- Historical stock data for context\n"
        "\nExample workflow:\n"
        "- User asks about Apple\n"
        "- You call get_apple_exec_info and get_apple_stock_price\n"
        "- You call get_apple_historical_price for trend context\n"
        "- You provide final answer combining all information\n"
        "\nDo NOT ask for clarification. Use your best judgment to gather comprehensive information."
    )
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"{user_input}\nAvailable tools:\n{tools_available}"}
    ]
    
    max_steps = 10
    final_answer_count = 0
    
    for step in range(max_steps):
        print(f"\n🔁 Step {step + 1}")
        llm_reply = call_llm(messages)
        print("🧠 Qwen Reply:")
        print(llm_reply)
        
        # Add the LLM's reply to messages first
        messages.append({"role": "assistant", "content": llm_reply})
        
        # Check if this is a final answer
        if is_final_answer(llm_reply):
            final_answer_count += 1
            if final_answer_count >= 2:  # If we get 2 final answers in a row, end conversation
                print(f"\n✅ Conversation Complete! (Received {final_answer_count} final answers)")
                break
            else:
                print(f"\n⚠️ Received final answer #{final_answer_count}, continuing...")
        else:
            final_answer_count = 0  # Reset counter if not a final answer
        
        # Parse and execute tool calls if present
        tool_calls = parse_tool_calls(llm_reply)
        if tool_calls:
            all_results = []
            for tool_call in tool_calls:
                tool_name = tool_call["tool"]
                tool_input = tool_call.get("input", {})
                
                if tool_name in tool_registry:
                    print(f"\n⚙️ Calling tool: {tool_name}")
                    try:
                        # Call the tool with input parameters if any
                        if tool_input:
                            result = tool_registry[tool_name](**tool_input)
                        else:
                            result = tool_registry[tool_name]()
                        
                        result_json = json.dumps(result, indent=2)
                        all_results.append(f"Tool '{tool_name}' result:\n{result_json}")
                        
                        print(f"📋 Tool Result: {result_json}")
                        
                    except Exception as e:
                        error_msg = f"Tool '{tool_name}' failed with error: {str(e)}"
                        all_results.append(error_msg)
                        print(f"❌ Tool Error: {error_msg}")
                else:
                    error_msg = f"Unknown tool: {tool_name}"
                    all_results.append(error_msg)
                    print(f"❌ {error_msg}")
            
            # Combine all tool results into one message
            if all_results:
                combined_results = "\n\n".join(all_results)
                tool_result_msg = f"Tool execution complete. Results:\n\n{combined_results}\n\nPlease analyze these results and either call another tool if you need more information, or provide your final answer starting with '✅ Final Answer:'."
                messages.append({"role": "user", "content": tool_result_msg})
                
        elif not is_final_answer(llm_reply):
            # No tool call detected, but also not a final answer
            # Prompt the model to continue or conclude
            prompt_msg = "Please either call another tool if you need more information, or provide your final answer starting with '✅ Final Answer:' if you have enough information."
            messages.append({"role": "user", "content": prompt_msg})
            print("💬 Prompting model to continue...")
    
    if step == max_steps - 1:
        print(f"\n⚠️ Reached maximum steps ({max_steps}). Ending conversation.")

if __name__ == "__main__":
    main()