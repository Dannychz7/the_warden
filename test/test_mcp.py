#!/usr/bin/env python3
"""
Simple test script for your MCP servers
Save this as test_mcp_servers.py
"""
import json
import subprocess
import time
import sys

def test_server(server_file, test_name):
    """Test a single MCP server"""
    print(f"\n{'='*50}")
    print(f"Testing {test_name}")
    print(f"{'='*50}")
    
    try:
        # Start server process
        process = subprocess.Popen(
            [sys.executable, server_file],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Test 1: Initialize
        print("\n1. Testing initialization...")
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
        }
        
        process.stdin.write(json.dumps(init_request) + '\n')
        process.stdin.flush()
        
        response = process.stdout.readline()
        if response:
            print(f"✓ Initialize: {json.loads(response).get('result', {}).get('serverInfo', {}).get('name', 'OK')}")
        else:
            print("✗ No response to initialize")
        
        # Test 2: List tools
        print("2. Testing tools list...")
        tools_request = {
            "jsonrpc": "2.0", 
            "id": 2,
            "method": "tools/list"
        }
        
        process.stdin.write(json.dumps(tools_request) + '\n')
        process.stdin.flush()
        
        response = process.stdout.readline()
        if response:
            tools_data = json.loads(response)
            tools = tools_data.get('result', {}).get('tools', [])
            print(f"✓ Found {len(tools)} tools:")
            for tool in tools:
                print(f"   - {tool.get('name', 'Unknown')}: {tool.get('description', 'No description')[:60]}...")
        else:
            print("✗ No response to tools/list")
        
        # Test 3: Call a tool (server-specific)
        print("3. Testing tool call...")
        if 'abuseIP' in server_file:
            tool_request = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "check_ip_reputation",
                    "arguments": {"ip": "8.8.8.8"}  # Google DNS - should be clean
                }
            }
        else:  # ThreatFox
            # tool_request = {
            #     "jsonrpc": "2.0", 
            #     "id": 3,
            #     "method": "tools/call",
            #     "params": {
            #         "name": "get_recent_iocs",
            #         "arguments": {"days": 1, "limit": 3}
            #     }
            # }

            tool_request = {
                "jsonrpc": "2.0", 
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "search_ioc",
                    "arguments": {"ioc": "134.122.177.12"}
                }
            }

        
        process.stdin.write(json.dumps(tool_request) + '\n')
        process.stdin.flush()
        
        response = process.stdout.readline()
        if response:
            result = json.loads(response)
            if 'result' in result:
                print("✓ Tool call successful")
                # Print first few lines of response
                content = result.get('result', {}).get('content', [{}])[0].get('text', '')
                if content:
                    # Parse and show summary
                    try:
                        data = json.loads(content)
                        if 'abuseIP' in server_file:
                            print(f"   IP: {data.get('ip', 'N/A')}")
                            print(f"   Threat Level: {data.get('threat_level', 'N/A')}")
                            print(f"   Confidence: {data.get('abuseConfidenceScore', 'N/A')}%")
                            print(f"   Number of Reports: {data.get('total_reports', 'N/A')}")
                        else:
                            print(data)
                            print(f"   Total IOCs: {data.get('total_results', 'N/A')}")
                            iocs = data.get('iocs', [])
                            if iocs:
                                print(f"   Sample IOC: {iocs[0].get('ioc', 'N/A')}")
                    except:
                        print(f"   Response preview: {content[:100]}...")
            else:
                print(f"✗ Tool call failed: {result.get('error', 'Unknown error')}")
        else:
            print("✗ No response to tool call")
        
        # Cleanup
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            
    except Exception as e:
        print(f"✗ Test failed with exception: {str(e)}")

def main():
    print("MCP Threat Intelligence Servers Test")
    print("====================================")
    
    # Check if .env file exists
    try:
        with open('.env', 'r') as f:
            env_content = f.read()
            if 'your_abuseipdb_api_key_here' in env_content:
                print("\n  WARNING: Please update your .env file with real API keys!")
                print("   Edit .env and replace 'your_abuseipdb_api_key_here' with your actual API key")
                print("   Get your key from: https://www.abuseipdb.com/api")
    except FileNotFoundError:
        print("\n No .env file found. Creating template...")
        with open('.env', 'w') as f:
            f.write("# AbuseIPDB API Key (required)\n")
            f.write("ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here\n")
            f.write("# ThreatFox API Key (optional)\n")
            f.write("THREATFOX_API_KEY=your_optional_threatfox_key\n")
        print("   Please edit .env with your API keys before running tests")
        return
    
    # Test both servers
    test_server('abuseIP_mcp_server.py', 'AbuseIPDB Server')
    test_server('threatFox_mcp_server.py', 'ThreatFox Server')
    
    print(f"\n{'='*50}")
    print("Test Summary")
    print(f"{'='*50}")
    print("If both servers responded correctly, they're ready to use!")
    print("\nNext steps:")
    print("1. Add the server configs to your MCP client")
    print("2. Start using them with your LLM/agent")
    print("\nExample MCP client config:")
    print("""
{
  "mcpServers": {
    "abuseipdb": {
      "command": "python3",
      "args": ["./abuseIP_mcp_server.py"],
      "env": {"ABUSEIPDB_API_KEY": "your-key"}
    },
    "threatfox": {
      "command": "python3", 
      "args": ["./threatFox_mcp_server.py"]
    }
  }
}
    """)

if __name__ == "__main__":
    main()