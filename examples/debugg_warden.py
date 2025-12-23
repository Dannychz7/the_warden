#!/usr/bin/env python3
"""
debug_warden.py - Debug and test The Warden components
"""
import json
from mcp_manager import MCPManager
from tool_executor import ToolExecutor

def test_mcp_servers():
    """Test MCP servers directly (similar to your test_mcp.py)"""
    print(" Testing MCP Servers...")
    
    manager = MCPManager("mcp_server_config.json")
    
    # Start servers
    if not manager.start_all_servers():
        print(" Failed to start servers")
        return False
    
    # Test each server
    for server_name, server in manager.servers.items():
        if server.is_connected:
            print(f"\n Testing {server_name}:")
            print(f"   Tools available: {len(server.tools)}")
            for tool in server.tools:
                tool_name = tool.get('name', 'Unknown')
                print(f"   - {tool_name}: {tool.get('description', 'No description')[:50]}...")
            
            # Test a tool call
            if server_name == 'abuseipdb-server':
                print(f"   🔧 Testing check_ip_reputation...")
                result = server.call_tool('check_ip_reputation', {'ip': '8.8.8.8'})
                if result:
                    print(f"    Raw result keys: {list(result.keys())}")
                    if 'result' in result:
                        content = result.get('result', {}).get('content', [])
                        if content and len(content) > 0:
                            text = content[0].get('text', '')[:100]
                            print(f"    Content preview: {text}...")
                        else:
                            print(f"     No content in result")
                    elif 'error' in result:
                        print(f"    Error: {result['error']}")
                else:
                    print(f"    No result returned")
            
            elif server_name == 'threatfox-server':
                print(f"    Testing search_ioc...")
                result = server.call_tool('search_ioc', {'ioc': '134.122.177.12'})
                if result:
                    print(f"    Raw result keys: {list(result.keys())}")
                    if 'result' in result:
                        content = result.get('result', {}).get('content', [])
                        if content and len(content) > 0:
                            text = content[0].get('text', '')[:100]
                            print(f"    Content preview: {text}...")
                        else:
                            print(f"     No content in result")
                    elif 'error' in result:
                        print(f"    Error: {result['error']}")
                else:
                    print(f"    No result returned")
    
    # Cleanup
    manager.stop_all_servers()
    return True

def test_tool_executor():
    """Test the tool executor"""
    print("\n Testing Tool Executor...")
    
    manager = MCPManager("mcp_server_config.json")
    executor = ToolExecutor(manager)
    
    # Start servers
    if not manager.start_all_servers():
        print(" Failed to start servers")
        return False
    
    # Set available tools
    tools = manager.get_all_tools()
    executor.set_available_tools(tools)
    
    print(f" Available tools: {executor.list_available_tools()}")
    
    # Test tool execution
    print("\n Testing check_ip_reputation...")
    result = executor.execute_tool('check_ip_reputation', {'ip': '8.8.8.8'})
    if result:
        print(f" Processed result: {json.dumps(result, indent=2)}")
    else:
        print(" No result from tool executor")
    
    print("\n Testing search_ioc...")
    result = executor.execute_tool('search_ioc', {'ioc': '134.122.177.12'})
    if result:
        print(f" Processed result: {json.dumps(result, indent=2)}")
    else:
        print(" No result from tool executor")
    
    # Cleanup
    manager.stop_all_servers()
    return True

def check_config():
    """Check configuration file and .env file"""
    print("  Checking configuration...")
    
    # Check main config
    try:
        with open("mcp_server_config.json", 'r') as f:
            config = json.load(f)
        
        print("Config file loaded successfully")
        
        servers = config.get('mcpServers', {})
        print(f" Found {len(servers)} servers:")
        
        for name, server_config in servers.items():
            print(f"\n   {name}:")
            print(f"   - Command: {server_config.get('command', 'Not set')}")
            print(f"   - Args: {server_config.get('args', [])}")
        
    except FileNotFoundError:
        print(" Config file 'mcp_server_config.json' not found")
        return False
    except json.JSONDecodeError as e:
        print(f" Invalid JSON in config file: {e}")
        return False
    
    # Check .env file (this is what the MCP servers actually use)
    print(f"\n Checking .env file (used by MCP servers)...")
    try:
        with open('.env', 'r') as f:
            env_content = f.read()
        
        print(" .env file found")
        
        # Check for required API keys without showing values
        required_keys = ['ABUSEIPDB_API_KEY', 'THREATFOX_API_KEY']
        for key in required_keys:
            if key in env_content:
                # Check if it's still the placeholder
                if f'{key}=your_' in env_content or f'{key}=optional' in env_content:
                    print(f"  {key} appears to be a placeholder - update with real API key")
                else:
                    print(f" {key} is set")
            else:
                print(f" {key} not found in .env file")
        
        return True
        
    except FileNotFoundError:
        print(" .env file not found! MCP servers need this for API keys")
        print(" Create .env file with:")
        print("   ABUSEIPDB_API_KEY=your_actual_api_key_here")
        print("   THREATFOX_API_KEY=your_optional_threatfox_key")
        return False

def main():
    """Run debug tests"""
    print("  THE WARDEN DEBUG TOOL")
    print("=" * 50)
    
    # Check config first
    if not check_config():
        return
    
    # Test MCP servers
    print("\n" + "=" * 50)
    if not test_mcp_servers():
        return
    
    # Test tool executor
    print("\n" + "=" * 50)
    test_tool_executor()
    
    print("\n" + "=" * 50)
    print(" Debug tests complete!")

if __name__ == "__main__":
    main()
