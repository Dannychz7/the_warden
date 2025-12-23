#!/usr/bin/env python3
"""
Elasticsearch MCP Server
Provides Elasticsearch querying capabilities for SIEM operations
"""

import asyncio
import json
import sys
import os
import requests
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class ElasticsearchServer:
    def __init__(self):
        self.name = "elasticsearch-server"
        self.version = "1.0.0"
        
        # For development - hardcoded, but configurable for future
        self.host = "192.168.1.222"
        self.port = "5000"
        # Future configuration via environment variables:
        # self.host = os.getenv("ELASTICSEARCH_HOST", "192.168.1.222")
        # self.port = os.getenv("ELASTICSEARCH_PORT", "5000")
        # self.username = os.getenv("ELASTICSEARCH_USERNAME")
        # self.password = os.getenv("ELASTICSEARCH_PASSWORD")
        
        self.base_url = f"http://{self.host}:{self.port}"
        self.default_limit = 5

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
                "name": "search_ip_across_indices",
                "description": "Search for an IP address across all Elasticsearch indices. Useful for tracking IP activity across different log sources.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IP address to search for"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results to return (default: 5)",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 100
                        }
                    },
                    "required": ["ip"]
                }
            },
            {
                "name": "search_username_across_indices",
                "description": "Search for a username across all Elasticsearch indices. Useful for tracking user activity across different systems.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                            "description": "Username to search for"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results to return (default: 5)",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 100
                        }
                    },
                    "required": ["username"]
                }
            },
            {
                "name": "list_indices",
                "description": "Get all available Elasticsearch indices with their health status, document counts, and storage information.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "search_index",
                "description": "Search within a specific Elasticsearch index using query string or match queries.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Index name to search in"
                        },
                        "query": {
                            "type": "string",
                            "description": "Search query string"
                        },
                        "field": {
                            "type": "string",
                            "description": "Specific field to search in (optional, defaults to all fields)",
                            "default": "_all"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results to return (default: 5)",
                            "default": 5,
                            "minimum": 1,
                            "maximum": 100
                        }
                    },
                    "required": ["index", "query"]
                }
            },
            {
                "name": "get_document",
                "description": "Get a specific document by its ID from an index.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Index name"
                        },
                        "doc_id": {
                            "type": "string",
                            "description": "Document ID"
                        }
                    },
                    "required": ["index", "doc_id"]
                }
            },
            {
                "name": "get_index_mapping",
                "description": "Get the field mappings for a specific index to understand its structure.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Index name"
                        }
                    },
                    "required": ["index"]
                }
            },
            {
                "name": "cluster_health",
                "description": "Check the health status of the Elasticsearch cluster.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "count_documents",
                "description": "Count documents in an index, optionally with a query filter.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Index name"
                        },
                        "query": {
                            "type": "string",
                            "description": "Optional query to filter documents (default: match all)",
                            "default": "*"
                        }
                    },
                    "required": ["index"]
                }
            },
            {
                "name": "execute_dsl_query",
                "description": "Execute a raw Elasticsearch Query DSL query for advanced operations like aggregations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Index name or pattern (use * for all indices)"
                        },
                        "query_dsl": {
                            "type": "object",
                            "description": "Raw Elasticsearch Query DSL as JSON object"
                        }
                    },
                    "required": ["index", "query_dsl"]
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

        try:
            if tool_name == "search_ip_across_indices":
                result = await self.search_ip_across_indices(
                    arguments.get("ip"),
                    arguments.get("limit", self.default_limit)
                )
            elif tool_name == "search_username_across_indices":
                result = await self.search_username_across_indices(
                    arguments.get("username"),
                    arguments.get("limit", self.default_limit)
                )
            elif tool_name == "list_indices":
                result = await self.list_indices()
            elif tool_name == "search_index":
                result = await self.search_index(
                    arguments.get("index"),
                    arguments.get("query"),
                    arguments.get("field", "_all"),
                    arguments.get("limit", self.default_limit)
                )
            elif tool_name == "get_document":
                result = await self.get_document(
                    arguments.get("index"),
                    arguments.get("doc_id")
                )
            elif tool_name == "get_index_mapping":
                result = await self.get_index_mapping(arguments.get("index"))
            elif tool_name == "cluster_health":
                result = await self.cluster_health()
            elif tool_name == "count_documents":
                result = await self.count_documents(
                    arguments.get("index"),
                    arguments.get("query", "*")
                )
            elif tool_name == "execute_dsl_query":
                result = await self.execute_dsl_query(
                    arguments.get("index"),
                    arguments.get("query_dsl")
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
        except Exception as e:
            return self.error_response(request_id, -32603, f"Tool execution error: {str(e)}")

    async def search_ip_across_indices(self, ip: str, limit: int = 10) -> Dict[str, Any]:
        """Search for an IP address across all indices"""
        if not ip:
            return {"error": "IP address is required"}

        # Get all indices first
        indices_result = await self.list_indices()
        if "error" in indices_result:
            return indices_result

        indices = [idx["index"] for idx in indices_result.get("indices", [])]
        
        # Search across all indices
        query = {
            "query": {
                "query_string": {
                    "query": ip,
                    "default_operator": "AND"
                }
            },
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}] if "@timestamp" else []
        }

        url = f"{self.base_url}/*/_search"
        
        try:
            response = requests.post(url, json=query, timeout=30)
            
            if response.status_code != 200:
                return {
                    "error": f"Elasticsearch error: HTTP {response.status_code}",
                    "details": response.text[:500]
                }

            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            
            results = []
            for hit in hits:
                results.append({
                    "index": hit.get("_index"),
                    "id": hit.get("_id"),
                    "score": hit.get("_score"),
                    "source": hit.get("_source", {})
                })

            return {
                "ip_searched": ip,
                "total_hits": data.get("hits", {}).get("total", {}).get("value", 0),
                "results_returned": len(results),
                "results": results,
                "took_ms": data.get("took", 0)
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def search_username_across_indices(self, username: str, limit: int = 10) -> Dict[str, Any]:
        """Search for a username across all indices"""
        if not username:
            return {"error": "Username is required"}

        query = {
            "query": {
                "match": {
                    "username": username
                }
            },
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}] if "@timestamp" else []
        }

        url = f"{self.base_url}/*/_search"
        
        try:
            response = requests.post(url, json=query, timeout=30)
            
            if response.status_code != 200:
                return {
                    "error": f"Elasticsearch error: HTTP {response.status_code}",
                    "details": response.text[:500]
                }

            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            
            results = []
            for hit in hits:
                results.append({
                    "index": hit.get("_index"),
                    "id": hit.get("_id"),
                    "score": hit.get("_score"),
                    "source": hit.get("_source", {})
                })

            return {
                "username_searched": username,
                "total_hits": data.get("hits", {}).get("total", {}).get("value", 0),
                "results_returned": len(results),
                "results": results,
                "took_ms": data.get("took", 0)
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def list_indices(self) -> Dict[str, Any]:
        """Get all available indices"""
        url = f"{self.base_url}/_cat/indices?v&format=json"
        
        try:
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                return {
                    "error": f"Elasticsearch error: HTTP {response.status_code}",
                    "details": response.text[:500]
                }

            data = response.json()
            
            # Format the response for better readability
            indices = []
            for index_info in data:
                indices.append({
                    "index": index_info.get("index"),
                    "health": index_info.get("health"),
                    "status": index_info.get("status"),
                    "docs_count": index_info.get("docs.count"),
                    "docs_deleted": index_info.get("docs.deleted"),
                    "store_size": index_info.get("store.size"),
                    "pri_store_size": index_info.get("pri.store.size")
                })

            return {
                "total_indices": len(indices),
                "indices": indices
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def search_index(self, index: str, query: str, field: str = "_all", limit: int = 5) -> Dict[str, Any]:
        """Search within a specific index"""
        if not index or not query:
            return {"error": "Both index and query are required"}

        if field == "_all":
            es_query = {
                "query": {
                    "query_string": {
                        "query": query,
                        "default_operator": "AND"
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}] if "@timestamp" else []
            }
        else:
            es_query = {
                "query": {
                    "match": {
                        field: query
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}] if "@timestamp" else []
            }

        url = f"{self.base_url}/{index}/_search"
        
        try:
            response = requests.post(url, json=es_query, timeout=30)
            
            if response.status_code != 200:
                return {
                    "error": f"Elasticsearch error: HTTP {response.status_code}",
                    "details": response.text[:500]
                }

            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            
            results = []
            for hit in hits:
                results.append({
                    "id": hit.get("_id"),
                    "score": hit.get("_score"),
                    "source": hit.get("_source", {})
                })

            return {
                "index": index,
                "query": query,
                "field": field,
                "total_hits": data.get("hits", {}).get("total", {}).get("value", 0),
                "results_returned": len(results),
                "results": results,
                "took_ms": data.get("took", 0)
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def get_document(self, index: str, doc_id: str) -> Dict[str, Any]:
        """Get a specific document by ID"""
        if not index or not doc_id:
            return {"error": "Both index and document ID are required"}

        url = f"{self.base_url}/{index}/_doc/{doc_id}"
        
        try:
            response = requests.get(url, timeout=10)
            
            if response.status_code == 404:
                return {"error": f"Document not found: {doc_id} in index {index}"}
            elif response.status_code != 200:
                return {
                    "error": f"Elasticsearch error: HTTP {response.status_code}",
                    "details": response.text[:500]
                }

            data = response.json()
            
            return {
                "index": data.get("_index"),
                "id": data.get("_id"),
                "version": data.get("_version"),
                "found": data.get("found"),
                "source": data.get("_source", {})
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def get_index_mapping(self, index: str) -> Dict[str, Any]:
        """Get field mappings for an index"""
        if not index:
            return {"error": "Index name is required"}

        url = f"{self.base_url}/{index}/_mapping"
        
        try:
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                return {
                    "error": f"Elasticsearch error: HTTP {response.status_code}",
                    "details": response.text[:500]
                }

            data = response.json()
            
            return {
                "index": index,
                "mappings": data
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def cluster_health(self) -> Dict[str, Any]:
        """Check cluster health"""
        url = f"{self.base_url}/_cluster/health"
        
        try:
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                return {
                    "error": f"Elasticsearch error: HTTP {response.status_code}",
                    "details": response.text[:500]
                }

            data = response.json()
            
            return {
                "cluster_name": data.get("cluster_name"),
                "status": data.get("status"),
                "timed_out": data.get("timed_out"),
                "number_of_nodes": data.get("number_of_nodes"),
                "number_of_data_nodes": data.get("number_of_data_nodes"),
                "active_primary_shards": data.get("active_primary_shards"),
                "active_shards": data.get("active_shards"),
                "relocating_shards": data.get("relocating_shards"),
                "initializing_shards": data.get("initializing_shards"),
                "unassigned_shards": data.get("unassigned_shards"),
                "delayed_unassigned_shards": data.get("delayed_unassigned_shards"),
                "number_of_pending_tasks": data.get("number_of_pending_tasks"),
                "number_of_in_flight_fetch": data.get("number_of_in_flight_fetch"),
                "task_max_waiting_in_queue_millis": data.get("task_max_waiting_in_queue_millis"),
                "active_shards_percent_as_number": data.get("active_shards_percent_as_number")
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def count_documents(self, index: str, query: str = "*") -> Dict[str, Any]:
        """Count documents in an index"""
        if not index:
            return {"error": "Index name is required"}

        if query == "*":
            es_query = {"query": {"match_all": {}}}
        else:
            es_query = {
                "query": {
                    "query_string": {
                        "query": query,
                        "default_operator": "AND"
                    }
                }
            }

        url = f"{self.base_url}/{index}/_count"
        
        try:
            response = requests.post(url, json=es_query, timeout=10)
            
            if response.status_code != 200:
                return {
                    "error": f"Elasticsearch error: HTTP {response.status_code}",
                    "details": response.text[:500]
                }

            data = response.json()
            
            return {
                "index": index,
                "query": query,
                "count": data.get("count", 0)
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    async def execute_dsl_query(self, index: str, query_dsl: Dict[str, Any]) -> Dict[str, Any]:
        """Execute raw Elasticsearch Query DSL"""
        if not index or not query_dsl:
            return {"error": "Both index and query_dsl are required"}

        url = f"{self.base_url}/{index}/_search"
        
        try:
            response = requests.post(url, json=query_dsl, timeout=30)
            
            if response.status_code != 200:
                return {
                    "error": f"Elasticsearch error: HTTP {response.status_code}",
                    "details": response.text[:500]
                }

            data = response.json()
            
            return {
                "index": index,
                "query_dsl": query_dsl,
                "elasticsearch_response": data
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Network request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

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
        print(f"Elasticsearch MCP Server v{self.version} starting...", file=sys.stderr)
        print(f"Connected to Elasticsearch at {self.base_url}", file=sys.stderr)
        print("Server capabilities: IP search, username search, index operations, document retrieval, DSL queries", file=sys.stderr)
        
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
    server = ElasticsearchServer()
    asyncio.run(server.run())