#!/usr/bin/env python3
"""
ThreatFox MCP Server
Provides threat intelligence data via the ThreatFox API from abuse.ch
"""

import asyncio
import json
import sys
import os
import requests
import ipaddress
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class ThreatFoxServer:
    def __init__(self):
        self.name = "threatfox-server"
        self.version = "1.0.0"
        self.api_key = os.getenv("THREATFOX_API_KEY")  # Optional
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"

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
                "name": "get_recent_iocs",
                "description": "Retrieve recent Indicators of Compromise (IOCs) from ThreatFox. I can fetch IP addresses, domains, URLs, and file hashes associated with malware and threats from the past few days.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "days": {
                            "type": "integer",
                            "description": "Number of days back to search (default: 1, max: 7)",
                            "default": 1,
                            "minimum": 1,
                            "maximum": 7
                        },
                        "ioc_type": {
                            "type": "string",
                            "enum": ["all", "ip", "domain", "url", "md5_hash", "sha1_hash", "sha256_hash"],
                            "description": "Filter by IOC type (default: all)",
                            "default": "all"
                        },
                        "malware_family": {
                            "type": "string",
                            "description": "Filter by specific malware family (optional)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results to return (default: 100)",
                            "default": 100,
                            "minimum": 1,
                            "maximum": 1000
                        }
                    }
                }
            },
            {
                "name": "search_ioc",
                "description": "Search for a specific IOC (IP, domain, URL, or hash) in ThreatFox database. I can tell you if an indicator has been reported as malicious and provide associated threat details.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ioc": {
                            "type": "string",
                            "description": "The IOC to search for (IP, domain, URL, or hash)"
                        }
                    },
                    "required": ["ioc"]
                }
            },
            {
                "name": "get_malware_info",
                "description": "Get information about a specific malware family from ThreatFox. I can provide recent IOCs, threat types, and activity patterns for known malware families.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "malware": {
                            "type": "string",
                            "description": "Malware family name (e.g., 'Emotet', 'TrickBot', 'Cobalt Strike')"
                        },
                        "days": {
                            "type": "integer",
                            "description": "Number of days back to search (default: 7)",
                            "default": 7,
                            "minimum": 1,
                            "maximum": 30
                        }
                    },
                    "required": ["malware"]
                }
            },
            {
                "name": "get_ip_iocs",
                "description": "Get all IP-based IOCs from recent ThreatFox data. Useful for network security monitoring and blocking malicious IPs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "days": {
                            "type": "integer",
                            "description": "Number of days back to search (default: 1)",
                            "default": 1,
                            "minimum": 1,
                            "maximum": 7
                        },
                        "confidence_threshold": {
                            "type": "integer",
                            "description": "Minimum confidence level (0-100)",
                            "default": 50,
                            "minimum": 0,
                            "maximum": 100
                        }
                    }
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

        if tool_name == "get_recent_iocs":
            result = await self.get_recent_iocs(
                arguments.get("days", 1),
                arguments.get("ioc_type", "all"),
                arguments.get("malware_family"),
                arguments.get("limit", 100)
            )
        elif tool_name == "search_ioc":
            result = await self.search_ioc(arguments.get("ioc"))
        elif tool_name == "get_malware_info":
            result = await self.get_malware_info(
                arguments.get("malware"),
                arguments.get("days", 7)
            )
        elif tool_name == "get_ip_iocs":
            result = await self.get_ip_iocs(
                arguments.get("days", 1),
                arguments.get("confidence_threshold", 50)
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

    async def get_recent_iocs(self, days: int = 1, ioc_type: str = "all", 
                            malware_family: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """Get recent IOCs from ThreatFox"""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        payload = {
            "query": "get_iocs",
            "days": days
        }

        try:
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=15)
            data = response.json()

            if data.get("query_status") != "ok":
                return {"error": "ThreatFox API error", "details": data}

            iocs = data.get("data", [])
            
            # Filter by IOC type
            if ioc_type != "all":
                if ioc_type == "ip":
                    iocs = [ioc for ioc in iocs if ioc.get("ioc_type") in ["ip:port", "ip"]]
                else:
                    iocs = [ioc for ioc in iocs if ioc.get("ioc_type") == ioc_type]
            
            # Filter by malware family
            if malware_family:
                iocs = [ioc for ioc in iocs if malware_family.lower() in ioc.get("malware", "").lower()]
            
            # Limit results
            iocs = iocs[:limit]
            
            # Process and format results
            processed_iocs = []
            for ioc in iocs:
                processed_ioc = {
                    "ioc": ioc.get("ioc", ""),
                    "ioc_type": ioc.get("ioc_type", ""),
                    "threat_type": ioc.get("threat_type", "Unknown"),
                    "malware": ioc.get("malware", "Unknown"),
                    "confidence_level": ioc.get("confidence_level", 0),
                    "first_seen": ioc.get("first_seen", ""),
                    "last_seen": ioc.get("last_seen", ""),
                    "tags": ioc.get("tags", []),
                    "reporter": ioc.get("reporter", "Unknown"),
                    "source": "ThreatFox"
                }
                
                # Additional processing for IP addresses
                if ioc.get("ioc_type") in ["ip:port", "ip"]:
                    ip_addr = ioc.get("ioc", "").split(":")[0]
                    try:
                        ipaddress.ip_address(ip_addr)
                        processed_ioc["validated_ip"] = ip_addr
                    except ValueError:
                        continue
                
                processed_iocs.append(processed_ioc)

            return {
                "total_results": len(processed_iocs),
                "query_parameters": {
                    "days": days,
                    "ioc_type": ioc_type,
                    "malware_family": malware_family,
                    "limit": limit
                },
                "iocs": processed_iocs,
                "source": "ThreatFox"
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"ThreatFox request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def search_ioc(self, ioc: str) -> Dict[str, Any]:
        """Search for a specific IOC"""
        if not ioc:
            return {"error": "IOC parameter is required"}

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        payload = {
            "query": "search_ioc",
            "search_term": ioc
        }

        try:
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=10)
            data = response.json()

            if data.get("query_status") == "no_result":
                return {
                    "ioc": ioc,
                    "found": False,
                    "message": "IOC not found in ThreatFox database",
                    "source": "ThreatFox"
                }
            
            if data.get("query_status") != "ok":
                return {"error": "ThreatFox API error", "details": data}

            results = data.get("data", [])
            
            return {
                "ioc": ioc,
                "found": True,
                "total_matches": len(results),
                "results": results,
                "source": "ThreatFox"
            }

        except Exception as e:
            return {"error": f"Search request failed: {str(e)}"}

    async def get_malware_info(self, malware: str, days: int = 7) -> Dict[str, Any]:
        """Get information about specific malware family"""
        if not malware:
            return {"error": "Malware family name is required"}

        # First get recent IOCs
        recent_data = await self.get_recent_iocs(days, "all", malware, 500)
        
        if "error" in recent_data:
            return recent_data

        iocs = recent_data.get("iocs", [])
        
        if not iocs:
            return {
                "malware_family": malware,
                "found": False,
                "message": f"No recent IOCs found for {malware} in the last {days} days",
                "source": "ThreatFox"
            }

        # Analyze the data
        threat_types = {}
        ioc_types = {}
        tags = {}
        
        for ioc in iocs:
            # Count threat types
            threat_type = ioc.get("threat_type", "Unknown")
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            # Count IOC types
            ioc_type = ioc.get("ioc_type", "Unknown")
            ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
            
            # Count tags
            for tag in ioc.get("tags", []):
                tags[tag] = tags.get(tag, 0) + 1

        return {
            "malware_family": malware,
            "found": True,
            "analysis_period_days": days,
            "total_iocs": len(iocs),
            "threat_type_distribution": threat_types,
            "ioc_type_distribution": ioc_types,
            "common_tags": dict(sorted(tags.items(), key=lambda x: x[1], reverse=True)[:10]),
            "recent_iocs": iocs[:20],  # Show first 20 IOCs
            "source": "ThreatFox"
        }

    async def get_ip_iocs(self, days: int = 1, confidence_threshold: int = 50) -> Dict[str, Any]:
        """Get IP-based IOCs for network security"""
        recent_data = await self.get_recent_iocs(days, "all", None, 1000)
        
        if "error" in recent_data:
            return recent_data

        all_iocs = recent_data.get("iocs", [])
        
        # Filter for IP-based IOCs
        ip_iocs = []
        for ioc in all_iocs:
            if ioc.get("ioc_type") in ["ip:port", "ip"] and ioc.get("confidence_level", 0) >= confidence_threshold:
                ip_addr = ioc.get("ioc", "").split(":")[0]
                try:
                    ipaddress.ip_address(ip_addr)
                    ioc["clean_ip"] = ip_addr
                    ip_iocs.append(ioc)
                except ValueError:
                    continue

        # Create summary for network administrators
        unique_ips = list(set([ioc["clean_ip"] for ioc in ip_iocs]))
        
        return {
            "analysis_period_days": days,
            "confidence_threshold": confidence_threshold,
            "total_ip_iocs": len(ip_iocs),
            "unique_ip_addresses": len(unique_ips),
            "ip_blocklist": unique_ips,
            "detailed_iocs": ip_iocs,
            "summary": {
                "high_confidence": len([ioc for ioc in ip_iocs if ioc.get("confidence_level", 0) >= 75]),
                "medium_confidence": len([ioc for ioc in ip_iocs if 50 <= ioc.get("confidence_level", 0) < 75]),
                "low_confidence": len([ioc for ioc in ip_iocs if ioc.get("confidence_level", 0) < 50])
            },
            "source": "ThreatFox"
        }

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
        print(f"ThreatFox MCP Server v{self.version} starting...", file=sys.stderr)
        print("Server capabilities: IOC retrieval, threat intelligence, malware analysis", file=sys.stderr)
        
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
    server = ThreatFoxServer()
    asyncio.run(server.run())