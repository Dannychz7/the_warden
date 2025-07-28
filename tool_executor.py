"""
tool_executor.py - Handles tool execution and result processing
"""
import json
from typing import Dict, List, Any, Optional
from mcp_manager import MCPManager

class ToolExecutor:
    """Executes tools and processes results for the Warden"""
    
    def __init__(self, mcp_manager: MCPManager):
        self.mcp_manager = mcp_manager
        self.available_tools = []
        self.execution_stats = {
            'total_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'tool_usage': {}
        }
    
    def set_available_tools(self, tools: List[Dict[str, Any]]):
        """Set the list of available tools"""
        self.available_tools = tools
        print(f"[TOOL] {len(tools)} tools available")
    
    def get_tool_descriptions(self) -> List[Dict[str, str]]:
        """Get simplified tool descriptions for the LLM"""
        descriptions = []
        for tool in self.available_tools:
            descriptions.append({
                'name': tool.get('name', 'Unknown'),
                'description': tool.get('description', 'No description'),
                'server': tool.get('server', 'Unknown')
            })
        return descriptions
    
    def get_tools_by_server(self) -> Dict[str, List[Dict[str, str]]]:
        """Get tools grouped by server"""
        tools_by_server = {}
        for tool in self.available_tools:
            server_name = tool.get('server', 'Unknown')
            if server_name not in tools_by_server:
                tools_by_server[server_name] = []
            
            tools_by_server[server_name].append({
                'name': tool.get('name', 'Unknown'),
                'description': tool.get('description', 'No description')
            })
        
        return tools_by_server
    
    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Execute a specific tool with given arguments"""
        print(f"[TOOL] Executing {tool_name} with args: {arguments}")
        
        # Update stats
        self.execution_stats['total_calls'] += 1
        if tool_name not in self.execution_stats['tool_usage']:
            self.execution_stats['tool_usage'][tool_name] = 0
        self.execution_stats['tool_usage'][tool_name] += 1
        
        # Validate tool exists
        if not self._tool_exists(tool_name):
            print(f"[TOOL] Tool '{tool_name}' not found")
            self.execution_stats['failed_calls'] += 1
            return {
                'tool': tool_name,
                'status': 'error',
                'error': f"Tool '{tool_name}' not found",
                'available_tools': self.list_available_tools()
            }
        
        # Validate arguments based on tool schema
        validation_result = self._validate_arguments(tool_name, arguments)
        if not validation_result['valid']:
            print(f"[TOOL] Invalid arguments for {tool_name}: {validation_result['error']}")
            self.execution_stats['failed_calls'] += 1
            return {
                'tool': tool_name,
                'status': 'error',
                'error': f"Invalid arguments: {validation_result['error']}",
                'expected_schema': validation_result.get('schema')
            }
        
        # Call the tool via MCP manager
        raw_result = self.mcp_manager.call_tool(tool_name, arguments)
        
        if not raw_result:
            print(f"[TOOL] Tool execution failed - no response")
            self.execution_stats['failed_calls'] += 1
            return {
                'tool': tool_name,
                'status': 'error',
                'error': 'No response from tool execution'
            }
        
        # Check for JSON-RPC errors
        if 'error' in raw_result:
            error_info = raw_result['error']
            print(f"[TOOL] Tool execution error: {error_info}")
            self.execution_stats['failed_calls'] += 1
            return {
                'tool': tool_name,
                'status': 'error',
                'error': error_info.get('message', 'Unknown error'),
                'error_code': error_info.get('code'),
                'raw_error': error_info
            }
        
        # Process and clean up the result
        processed_result = self._process_tool_result(tool_name, raw_result)
        
        if processed_result.get('status') == 'success':
            self.execution_stats['successful_calls'] += 1
            print(f"[TOOL] Tool execution successful")
        else:
            self.execution_stats['failed_calls'] += 1
            print(f"[TOOL] Tool execution completed with issues")
        
        return processed_result
    
    def _tool_exists(self, tool_name: str) -> bool:
        """Check if a tool exists in the available tools"""
        for tool in self.available_tools:
            if tool.get('name') == tool_name:
                return True
        return False
    
    def _validate_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Validate arguments against tool schema"""
        tool_info = self.get_tool_help(tool_name)
        if not tool_info:
            return {'valid': False, 'error': 'Tool not found'}
        
        schema = tool_info.get('inputSchema', {})
        properties = schema.get('properties', {})
        required = schema.get('required', [])
        
        # Check required fields
        for req_field in required:
            if req_field not in arguments:
                return {
                    'valid': False,
                    'error': f"Missing required field: {req_field}",
                    'schema': schema
                }
        
        # Basic type checking for common types
        for arg_name, arg_value in arguments.items():
            if arg_name in properties:
                expected_type = properties[arg_name].get('type')
                if expected_type == 'string' and not isinstance(arg_value, str):
                    return {
                        'valid': False,
                        'error': f"Field '{arg_name}' must be a string",
                        'schema': schema
                    }
                elif expected_type == 'integer' and not isinstance(arg_value, int):
                    return {
                        'valid': False,
                        'error': f"Field '{arg_name}' must be an integer",
                        'schema': schema
                    }
                elif expected_type == 'boolean' and not isinstance(arg_value, bool):
                    return {
                        'valid': False,
                        'error': f"Field '{arg_name}' must be a boolean",
                        'schema': schema
                    }
                elif expected_type == 'array' and not isinstance(arg_value, list):
                    return {
                        'valid': False,
                        'error': f"Field '{arg_name}' must be an array",
                        'schema': schema
                    }
        
        return {'valid': True}
    
    def _process_tool_result(self, tool_name: str, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw tool results into a clean format"""
        try:
            # Extract the actual result content
            if 'result' in raw_result and 'content' in raw_result['result']:
                content = raw_result['result']['content']
                
                if isinstance(content, list) and len(content) > 0:
                    # Get the text content from the first item
                    text_content = content[0].get('text', '')
                    
                    # Try to parse as JSON if it looks like JSON
                    if text_content.strip().startswith('{') or text_content.strip().startswith('['):
                        try:
                            parsed_data = json.loads(text_content)
                            
                            # Special processing for different tool types
                            if tool_name.startswith('search_') or tool_name.startswith('list_'):
                                # For search and list tools, provide summary info
                                summary = self._generate_result_summary(tool_name, parsed_data)
                                return {
                                    'tool': tool_name,
                                    'status': 'success',
                                    'data': parsed_data,
                                    'summary': summary,
                                    'raw_content': text_content
                                }
                            else:
                                return {
                                    'tool': tool_name,
                                    'status': 'success',
                                    'data': parsed_data,
                                    'raw_content': text_content
                                }
                        except json.JSONDecodeError as e:
                            print(f"[TOOL] JSON decode error for {tool_name}: {e}")
                            pass
                    
                    # Return as plain text if not JSON
                    return {
                        'tool': tool_name,
                        'status': 'success',
                        'data': text_content,
                        'raw_content': text_content
                    }
            
            # Fallback - return the raw result
            return {
                'tool': tool_name,
                'status': 'success',
                'data': raw_result,
                'raw_content': str(raw_result)
            }
            
        except Exception as e:
            print(f"[TOOL] Error processing result from {tool_name}: {e}")
            return {
                'tool': tool_name,
                'status': 'error',
                'error': str(e),
                'raw_result': raw_result
            }
    
    def _generate_result_summary(self, tool_name: str, data: Dict[str, Any]) -> str:
        """Generate a human-readable summary of tool results"""
        try:
            if tool_name == 'list_indices':
                total = data.get('total_indices', 0)
                return f"Found {total} Elasticsearch indices"
            
            elif tool_name.startswith('search_ip_'):
                ip = data.get('ip_searched', 'unknown')
                hits = data.get('total_hits', 0)
                return f"Found {hits} results for IP {ip}"
            
            elif tool_name.startswith('search_username_'):
                username = data.get('username_searched', 'unknown')
                hits = data.get('total_hits', 0)
                return f"Found {hits} results for username {username}"
            
            elif tool_name == 'cluster_health':
                status = data.get('status', 'unknown')
                nodes = data.get('number_of_nodes', 0)
                return f"Cluster status: {status} ({nodes} nodes)"
            
            elif tool_name == 'check_ip_reputation':
                ip = data.get('ip', 'unknown')
                confidence = data.get('abuseConfidenceScore', 0)
                threat = data.get('threat_level', 'unknown')
                return f"IP {ip}: {confidence}% confidence, threat level: {threat}"
            
            elif 'error' in data:
                return f"Error: {data['error']}"
            
            else:
                return f"Tool executed successfully"
                
        except Exception as e:
            return f"Summary generation failed: {str(e)}"
    
    def get_tool_help(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get help information for a specific tool"""
        for tool in self.available_tools:
            if tool.get('name') == tool_name:
                return {
                    'name': tool.get('name'),
                    'description': tool.get('description'),
                    'server': tool.get('server'),
                    'inputSchema': tool.get('inputSchema', {})
                }
        return None
    
    def list_available_tools(self) -> List[str]:
        """Get a list of available tool names"""
        return [tool.get('name', 'Unknown') for tool in self.available_tools]
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get tool execution statistics"""
        success_rate = 0
        if self.execution_stats['total_calls'] > 0:
            success_rate = (self.execution_stats['successful_calls'] / self.execution_stats['total_calls']) * 100
        
        return {
            **self.execution_stats,
            'success_rate': round(success_rate, 2)
        }
    
    def reset_stats(self):
        """Reset execution statistics"""
        self.execution_stats = {
            'total_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'tool_usage': {}
        }
        print("[TOOL] Statistics reset")
    
    def get_popular_tools(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get most frequently used tools"""
        sorted_tools = sorted(
            self.execution_stats['tool_usage'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {'tool': tool_name, 'usage_count': count}
            for tool_name, count in sorted_tools[:limit]
        ]