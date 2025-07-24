# requirements.txt
requests>=2.31.0
python-dotenv>=1.0.0
ipaddress  # Built-in for Python 3.3+

# .env file (create this with your API keys)
# ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
# THREATFOX_API_KEY=your_optional_threatfox_api_key

# setup.sh - Setup script
#!/bin/bash

echo "Setting up MCP Python Servers for Threat Intelligence..."

# Create virtual environment
python3 -m venv mcp_env
source mcp_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make servers executable
chmod +x abuseipdb_server.py
chmod +x threatfox_server.py

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file template..."
    cat > .env << 'EOF'
# AbuseIPDB API Key (required for AbuseIPDB server)
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# ThreatFox API Key (optional - public API available without key)
THREATFOX_API_KEY=your_optional_threatfox_api_key
EOF
    echo "Please edit .env file with your API keys"
fi

echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit the .env file with your API keys"
echo "2. Get AbuseIPDB API key from: https://www.abuseipdb.com/api"
echo "3. Get ThreatFox API key from: https://threatfox.abuse.ch/api/ (optional)"
echo "4. Test the servers:"
echo "   python3 abuseipdb_server.py"
echo "   python3 threatfox_server.py"
echo ""
echo "MCP Client Configuration:"
echo "Add the configuration from mcp_config.json to your MCP client"

# test_servers.py - Simple test script
cat > test_servers.py << 'EOF'
#!/usr/bin/env python3
"""
Simple test script for MCP servers
"""
import json
import subprocess
import sys
import time

def test_server(server_script, test_requests):
    """Test an MCP server with sample requests"""
    print(f"\n=== Testing {server_script} ===")
    
    try:
        # Start the server process
        process = subprocess.Popen(
            [sys.executable, server_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        for i, request in enumerate(test_requests):
            print(f"\nTest {i+1}: {request['method']}")
            
            # Send request
            request_json = json.dumps(request) + '\n'
            process.stdin.write(request_json)
            process.stdin.flush()
            
            # Read response
            response_line = process.stdout.readline()
            if response_line:
                try:
                    response = json.loads(response_line.strip())
                    print(f"✓ Response: {response.get('result', response.get('error', 'Unknown'))}")
                except json.JSONDecodeError:
                    print(f"✗ Invalid JSON response: {response_line}")
            else:
                print("✗ No response received")
            
            time.sleep(0.1)
        
        # Cleanup
        process.terminate()
        process.wait(timeout=5)
        
    except Exception as e:
        print(f"✗ Test failed: {str(e)}")

def main():
    # Test AbuseIPDB server
    abuseipdb_tests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
        },
        {
            "jsonrpc": "2.0", 
            "id": 2,
            "method": "tools/list"
        },
        {
            "jsonrpc": "2.0",
            "id": 3, 
            "method": "tools/call",
            "params": {
                "name": "check_ip_reputation",
                "arguments": {"ip": "8.8.8.8"}
            }
        }
    ]
    
    # Test ThreatFox server
    threatfox_tests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize", 
            "params": {"protocolVersion": "2024-11-05"}
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call", 
            "params": {
                "name": "get_recent_iocs",
                "arguments": {"days": 1, "limit": 5}
            }
        }
    ]
    
    test_server("abuseipdb_server.py", abuseipdb_tests)
    test_server("threatfox_server.py", threatfox_tests)

if __name__ == "__main__":
    main()
EOF

chmod +x test_servers.py

echo "Test script created: test_servers.py"