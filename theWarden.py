#!/usr/bin/env python3
"""
theWarden.py - Main Agent Controller
An autonomous SOC analyst that uses Qwen3 to make decisions about threat analysis
"""
import json
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime

from mcp_manager import MCPManager
from llm_interface import LLMInterface
from tool_executor import ToolExecutor

class TheWarden:
    """Main Warden Agent - Autonomous SOC Analyst"""
    
    def __init__(self, config_file: str = "mcp_server_config.json"):
        self.mcp_manager = MCPManager(config_file)
        self.llm = LLMInterface()
        self.tool_executor = ToolExecutor(self.mcp_manager)
        self.max_iterations = 5  # Prevent infinite loops
        
    def start(self):
        """Initialize the Warden system"""
        print("[WARDEN] The Warden is initializing...")
        
        if not self.mcp_manager.start_all_servers():
            print("[WARDEN] Failed to start threat intelligence servers")
            return False
            
        available_tools = self.mcp_manager.get_all_tools()
        self.tool_executor.set_available_tools(available_tools)
        
        print(f"[WARDEN] Online with {len(available_tools)} threat intelligence tools")
        for tool in available_tools:
            print(f"         {tool['name']} - {tool['description'][:60]}...")
            
        return True
    
    def shutdown(self):
        """Shutdown the Warden system"""
        print("[WARDEN] The Warden is shutting down...")
        self.mcp_manager.stop_all_servers()
    
    def analyze(self, user_query: str) -> str:
        """
        Main analysis function - Warden thinks and acts autonomously
        """
        print(f"[WARDEN] Analyzing: {user_query}")
        
        # Initialize the analysis session
        analysis_context = {
            "user_query": user_query,
            "iteration": 0,
            "tool_results": [],
            "analysis_complete": False
        }
        
        # Let Qwen3 think and act iteratively
        for iteration in range(self.max_iterations):
            analysis_context["iteration"] = iteration + 1
            
            print(f"[WARDEN] Thinking... (iteration {iteration + 1})")
            
            # Ask Qwen3 what to do next
            decision = self.llm.get_next_action(analysis_context, self.tool_executor.get_tool_descriptions())
            
            if not decision:
                print("[WARDEN] LLM communication error")
                break
                
            # Parse the decision
            action = decision.get("action", "complete")
            
            if action == "complete":
                print("[WARDEN] Analysis complete")
                break
            elif action == "use_tool":
                tool_name = decision.get("tool_name")
                tool_args = decision.get("arguments", {})
                
                print(f"[WARDEN] Using tool: {tool_name}")
                
                # Execute the tool
                tool_result = self.tool_executor.execute_tool(tool_name, tool_args)
                
                if tool_result:
                    analysis_context["tool_results"].append({
                        "tool": tool_name,
                        "arguments": tool_args,
                        "result": tool_result,
                        "iteration": iteration + 1
                    })
                else:
                    print(f"[WARDEN] Tool execution failed: {tool_name}")
            else:
                print(f"[WARDEN] Unknown action: {action}")
        
        # Generate final analysis report
        print("[WARDEN] Generating final analysis...")
        final_report = self.llm.generate_final_analysis(analysis_context)
        
        return final_report
    
    def interactive_mode(self):
        """Run Warden in interactive mode"""
        print("\n" + "=" * 70)
        print("    THE WARDEN - Autonomous SOC Analyst")
        print("    Powered by Qwen3 + Threat Intelligence APIs")
        print("=" * 70)
        
        if not self.start():
            return
            
        try:
            while True:
                print("\n[WARDEN] Ready for analysis...")
                user_input = input("Query: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'bye']:
                    break
                    
                if not user_input:
                    continue
                
                print()
                result = self.analyze(user_input)
                print("\n" + "=" * 70)
                print("THREAT ANALYSIS REPORT")
                print("=" * 70)
                print(result)
                print("=" * 70)
                
        except KeyboardInterrupt:
            print("\n[WARDEN] Interrupted by user")
        finally:
            self.shutdown()

def main():
    """Main entry point"""
    warden = TheWarden()
    
    if len(sys.argv) > 1:
        # Single query mode
        query = " ".join(sys.argv[1:])
        if warden.start():
            try:
                result = warden.analyze(query)
                print(result)
            finally:
                warden.shutdown()
    else:
        # Interactive mode
        warden.interactive_mode()

if __name__ == "__main__":
    import sys
    main()