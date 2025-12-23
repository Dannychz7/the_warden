#!/usr/bin/env python3
"""
AbuseIPDB MCP Server
Provides IP reputation checking capabilities via the AbuseIPDB API
"""

import asyncio
import json
import sys
import os
import requests
import ipaddress
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class AbuseIPDBServer:
    def __init__(self):
        self.name = "abuseipdb-server"
        self.version = "1.0.0"
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        
        if not self.api_key:
            print("Warning: ABUSEIPDB_API_KEY not found in environment", file=sys.stderr)

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming MCP requests"""
        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")

        try:
            if method == "initialize":
                return await self.handle_initialize(request_id, params)
            elif method == "tools/list":
                return await self.handle_list_tools(request_id)
            elif method == "tools/call":
                return await self.handle_call_tool(request_id, params)
            else:
                return self.error_response(request_id, -32601, f"Method not found: {method}")
        
        except Exception as e:
            return self.error_response(request_id, -32603, f"Internal error: {str(e)}")

    async def handle_initialize(self, request_id: int, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialization request"""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": self.name,
                    "version": self.version
                }
            }
        }

    async def handle_list_tools(self, request_id: int) -> Dict[str, Any]:
        """List available tools"""
        tools = [
            {
                "name": "check_ip_reputation",
                "description": "Check IP address reputation using AbuseIPDB. I can provide abuse confidence scores, country information, ISP details, and reporting history for any IP address.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IP address to check (IPv4 or IPv6)"
                        },
                        "max_age_days": {
                            "type": "integer",
                            "description": "Maximum age of reports to consider (default: 30 days)",
                            "default": 30,
                            "minimum": 1,
                            "maximum": 365
                        },
                        "verbose": {
                            "type": "boolean",
                            "description": "Include additional details in response",
                            "default": False
                        }
                    },
                    "required": ["ip"]
                }
            },
            {
                "name": "check_multiple_ips",
                "description": "Check multiple IP addresses for reputation in batch. Efficient for analyzing lists of IPs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ips": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of IP addresses to check",
                            "maxItems": 50
                        },
                        "max_age_days": {
                            "type": "integer",
                            "description": "Maximum age of reports to consider",
                            "default": 30
                        }
                    },
                    "required": ["ips"]
                }
            }
        ]

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": tools}
        }

    async def handle_call_tool(self, request_id: int, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool execution"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "check_ip_reputation":
            result = await self.check_ip_reputation(
                arguments.get("ip"),
                arguments.get("max_age_days", 30),
                arguments.get("verbose", False)
            )
        elif tool_name == "check_multiple_ips":
            result = await self.check_multiple_ips(
                arguments.get("ips", []),
                arguments.get("max_age_days", 30)
            )
        else:
            return self.error_response(request_id, -32602, f"Unknown tool: {tool_name}")

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, indent=2)
                    }
                ]
            }
        }

    async def check_ip_reputation(self, ip: str, max_age_days: int = 30, verbose: bool = False) -> Dict[str, Any]:
        """Check single IP reputation"""
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}

        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"error": f"Invalid IP address: {ip}"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(max_age_days),
            "verbose": "true" if verbose else "false"
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code != 200:
                return {
                    "error": f"AbuseIPDB API error: HTTP {response.status_code}",
                    "details": response.text[:200]
                }

            data = response.json()
            
            if "data" not in data:
                return {"error": "Unexpected AbuseIPDB response format", "details": str(data)}

            result_data = data["data"]
            
            # Format the response
            result = {
                "ip": ip,
                "abuseConfidenceScore": result_data.get("abuseConfidenceScore", 0),
                "country_code": result_data.get("countryCode", "Unknown"),
                "country_name": result_data.get("countryName", "Unknown"),
                "usage_type": result_data.get("usageType", "Unknown"),
                "isp": result_data.get("isp", "Unknown"),
                "domain": result_data.get("domain", "Unknown"),
                "total_reports": result_data.get("totalReports", 0),
                "num_distinct_users": result_data.get("numDistinctUsers", 0),
                "last_reported_at": result_data.get("lastReportedAt", "Never"),
                "is_public": result_data.get("isPublic", False),
                "is_whitelisted": result_data.get("isWhitelisted", False),
                "source": "AbuseIPDB",
                "threat_level": self.get_threat_level(result_data.get("abuseConfidenceScore", 0))
            }

            if verbose and "reports" in result_data:
                result["recent_reports"] = result_data["reports"][:5]  # Show last 5 reports

            return result

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def check_multiple_ips(self, ips: List[str], max_age_days: int = 30) -> Dict[str, Any]:
        """Check multiple IPs (sequential to avoid rate limiting)"""
        if not ips:
            return {"error": "No IP addresses provided"}
        
        if len(ips) > 50:
            return {"error": "Too many IPs provided (maximum 50)"}

        results = []
        errors = []

        for ip in ips:
            result = await self.check_ip_reputation(ip, max_age_days, False)
            
            if "error" in result:
                errors.append({"ip": ip, "error": result["error"]})
            else:
                results.append(result)
            
            # Small delay to avoid rate limiting
            await asyncio.sleep(0.1)

        return {
            "total_checked": len(ips),
            "successful_checks": len(results),
            "failed_checks": len(errors),
            "results": results,
            "errors": errors if errors else None
        }

    def get_threat_level(self, confidence: int) -> str:
        """Convert confidence percentage to threat level"""
        if confidence >= 75:
            return "HIGH"
        elif confidence >= 50:
            return "MEDIUM"
        elif confidence >= 25:
            return "LOW"
        else:
            return "CLEAN"

    def error_response(self, request_id: int, code: int, message: str) -> Dict[str, Any]:
        """Generate error response"""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": message
            }
        }

    async def run(self):
        """Main server loop"""
        print(f"AbuseIPDB MCP Server v{self.version} starting...", file=sys.stderr)
        print("Server capabilities: IP reputation checking, batch IP analysis", file=sys.stderr)
        
        try:
            while True:
                # Read JSON-RPC request from stdin
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                
                if not line:
                    break
                
                try:
                    request = json.loads(line.strip())
                    response = await self.handle_request(request)
                    
                    # Write response to stdout
                    print(json.dumps(response), flush=True)
                    
                except json.JSONDecodeError as e:
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32700,
                            "message": f"Parse error: {str(e)}"
                        }
                    }
                    print(json.dumps(error_response), flush=True)
                    
        except KeyboardInterrupt:
            print("Server shutting down...", file=sys.stderr)
        except Exception as e:
            print(f"Server error: {str(e)}", file=sys.stderr)

if __name__ == "__main__":
    server = AbuseIPDBServer()
    asyncio.run(server.run())