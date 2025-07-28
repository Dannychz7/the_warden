"""
mcp_manager.py - Manages MCP server connections and communication
"""
import json
import subprocess
import os
import time
from typing import Dict, List, Any, Optional

class MCPServer:
    """Represents a single MCP server connection"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.process = None
        self.tools = []
        self.is_connected = False
        self.startup_timeout = config.get('startup_timeout', 3.0)  # Allow configurable startup time
        
    def start(self) -> bool:
        """Start the MCP server process"""
        try:
            cmd = [self.config['command']] + self.config.get('args', [])
            env = os.environ.copy()
            
            # Note: MCP servers use dotenv to load API keys from .env file
            # The env config here is mainly for other environment variables
            config_env = self.config.get('env', {})
            if config_env:
                env.update(config_env)
                print(f"[MCP] Additional env vars for {self.name}: {list(config_env.keys())}")
            
            print(f"[MCP] Starting {self.name} with command: {' '.join(cmd)}")
            print(f"[MCP] Note: {self.name} will load API keys from .env file via dotenv")
            
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env
            )
            
            # Give the process a moment to start and load .env
            time.sleep(self.startup_timeout)
            
            # Check if process is still running
            if self.process.poll() is not None:
                stderr_output = self.process.stderr.read() if self.process.stderr else "No stderr output"
                print(f"[MCP] {self.name} process exited early. Error: {stderr_output}")
                return False
            
            # Initialize the server (matching test_mcp.py)
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"}
            }
            
            response = self._send_request(init_request)
            if response and 'result' in response:
                server_info = response.get('result', {}).get('serverInfo', {})
                server_name = server_info.get('name', 'Unknown')
                server_version = server_info.get('version', 'Unknown')
                print(f"[MCP] {self.name} initialized as '{server_name}' v{server_version}")
                self.is_connected = True
                self._load_tools()
                return True
            else:
                print(f"[MCP] Failed to initialize {self.name} - no valid response")
                if response:
                    print(f"[MCP] Response was: {response}")
                # Check stderr for any error messages
                if self.process.stderr:
                    stderr_line = self.process.stderr.readline()
                    if stderr_line:
                        print(f"[MCP] Stderr: {stderr_line.strip()}")
                
        except FileNotFoundError:
            print(f"[MCP] Command not found for {self.name}: {self.config['command']}")
        except Exception as e:
            print(f"[MCP] Failed to start {self.name}: {e}")
            
        return False
    
    def _send_request(self, request: Dict[str, Any], timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        """Send a JSON-RPC request to the server with timeout handling"""
        if not self.process:
            return None
            
        try:
            # Send request (matching test_mcp.py format)
            request_json = json.dumps(request) + '\n'
            self.process.stdin.write(request_json)
            self.process.stdin.flush()
            
            # Read response with timeout handling
            import select
            import sys
            
            # Use select for non-blocking read with timeout (Unix-like systems)
            if hasattr(select, 'select'):
                ready, _, _ = select.select([self.process.stdout], [], [], timeout)
                if not ready:
                    print(f"[MCP] Timeout waiting for response from {self.name}")
                    return None
            
            response_line = self.process.stdout.readline()
            if response_line:
                response = json.loads(response_line.strip())
                
                # Check for JSON-RPC errors
                if 'error' in response:
                    error_info = response['error']
                    print(f"[MCP] JSON-RPC error from {self.name}: {error_info.get('message', 'Unknown error')} (Code: {error_info.get('code', 'Unknown')})")
                
                return response
            else:
                print(f"[MCP] No response from {self.name}")
                return None
                
        except json.JSONDecodeError as e:
            print(f"[MCP] Invalid JSON response from {self.name}: {e}")
            print(f"[MCP] Raw response: {response_line if 'response_line' in locals() else 'None'}")
            return None
        except Exception as e:
            print(f"[MCP] Communication error with {self.name}: {e}")
            return None
    
    def _load_tools(self):
        """Load available tools from the server"""
        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }
        
        response = self._send_request(tools_request)
        if response and 'result' in response:
            self.tools = response['result'].get('tools', [])
            # Add server name to each tool for identification
            for tool in self.tools:
                tool['server'] = self.name
            print(f"[MCP] Loaded {len(self.tools)} tools from {self.name}")
        else:
            print(f"[MCP] Failed to load tools from {self.name}")
    
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call a specific tool on this server"""
        if not self.is_connected:
            print(f"[MCP] Server {self.name} is not connected")
            return None
            
        tool_request = {
            "jsonrpc": "2.0",
            "id": int(time.time() * 1000),  # Use milliseconds for better uniqueness
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }
        
        print(f"[MCP] Calling {tool_name} on {self.name} with args: {arguments}")
        response = self._send_request(tool_request, timeout=30.0)  # Longer timeout for tool calls
        
        if response and 'result' in response:
            print(f"[MCP] Tool {tool_name} executed successfully")
        elif response and 'error' in response:
            print(f"[MCP] Tool {tool_name} failed: {response['error']}")
        
        return response
    
    def stop(self):
        """Stop the server process"""
        if self.process:
            print(f"[MCP] Stopping {self.name}...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)  # Increased timeout
            except subprocess.TimeoutExpired:
                print(f"[MCP] Force killing {self.name}")
                self.process.kill()
            self.process = None
            self.is_connected = False
    
    def health_check(self) -> bool:
        """Check if the server is still responsive"""
        if not self.process or not self.is_connected:
            return False
            
        # Check if process is still running
        if self.process.poll() is not None:
            print(f"[MCP] {self.name} process has died")
            self.is_connected = False
            return False
            
        return True

class MCPManager:
    """Manages multiple MCP servers"""
    
    def __init__(self, config_file: str):
        self.servers = {}
        self.config_file = config_file
        self.client_settings = {}
        self._load_config()
    
    def _load_config(self):
        """Load MCP server configuration"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                
            # Load client settings
            self.client_settings = config.get('clientSettings', {})
            print(f"[MCP] Client settings: {self.client_settings}")
                
            for server_name, server_config in config.get('mcpServers', {}).items():
                # Merge client settings into server config if needed
                if 'startup_timeout' not in server_config and 'timeout' in self.client_settings:
                    server_config['startup_timeout'] = self.client_settings['timeout'] / 1000.0  # Convert ms to seconds
                    
                self.servers[server_name] = MCPServer(server_name, server_config)
                print(f"[MCP] Configured server: {server_name} - {server_config.get('description', 'No description')}")
                
        except FileNotFoundError:
            print(f"[MCP] Config file {self.config_file} not found")
            raise
        except json.JSONDecodeError as e:
            print(f"[MCP] Invalid JSON in config file: {e}")
            raise
    
    def start_all_servers(self) -> bool:
        """Start all configured MCP servers"""
        print("[MCP] Starting threat intelligence servers...")
        
        success_count = 0
        total_tools = 0
        
        for server_name, server in self.servers.items():
            print(f"[MCP] Starting {server_name}...")
            if server.start():
                tool_count = len(server.tools)
                print(f"[MCP] {server_name} online ({tool_count} tools)")
                success_count += 1
                total_tools += tool_count
            else:
                print(f"[MCP] {server_name} failed to start")
        
        if success_count > 0:
            print(f"[MCP] {success_count}/{len(self.servers)} servers started successfully")
            print(f"[MCP] Total tools available: {total_tools}")
        
        return success_count > 0
    
    def stop_all_servers(self):
        """Stop all MCP servers"""
        print("[MCP] Shutting down servers...")
        for server in self.servers.values():
            server.stop()
        print("[MCP] All servers stopped")
    
    def get_all_tools(self) -> List[Dict[str, Any]]:
        """Get all available tools from all servers"""
        all_tools = []
        for server in self.servers.values():
            if server.is_connected:
                all_tools.extend(server.tools)
        return all_tools
    
    def get_server_for_tool(self, tool_name: str) -> Optional[MCPServer]:
        """Find which server has a specific tool"""
        for server in self.servers.values():
            if server.is_connected:
                for tool in server.tools:
                    if tool.get('name') == tool_name:
                        return server
        return None
    
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call a tool on the appropriate server"""
        server = self.get_server_for_tool(tool_name)
        if server:
            return server.call_tool(tool_name, arguments)
        else:
            print(f"[MCP] Tool '{tool_name}' not found on any server")
            available_tools = [tool.get('name') for tool in self.get_all_tools()]
            print(f"[MCP] Available tools: {', '.join(available_tools)}")
        return None
    
    def health_check_all(self) -> Dict[str, bool]:
        """Check health of all servers"""
        health_status = {}
        for server_name, server in self.servers.items():
            health_status[server_name] = server.health_check()
        return health_status
    
    def get_server_status(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed status of all servers"""
        status = {}
        for server_name, server in self.servers.items():
            status[server_name] = {
                'connected': server.is_connected,
                'tools_count': len(server.tools),
                'description': server.config.get('description', 'No description'),
                'process_running': server.process is not None and server.process.poll() is None
            }
        return status