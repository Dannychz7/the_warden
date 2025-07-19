# tool_schema.py
tool_list = [
    {
        "name": "query_threatfox",
        "description": "Fetches IP-based threat intelligence indicators from ThreatFox within the past specified number of days.",
        "parameters": {
            "type": "object",
            "properties": {
                "days": {
                    "type": "integer",
                    "description": "Number of days back to query threat intelligence (default is 1)."
                }
            },
            "required": []
        }
    },
    {
        "name": "query_abuseip",
        "description": "Checks reputation and abuse data for a given IP address using the AbuseIPDB API.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The IP address to check for abuse reports."
                }
            },
            "required": ["ip"]
        }
    }
]
