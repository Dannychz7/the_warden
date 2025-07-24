# tools/intel_providers.py
import os
import requests
import ipaddress
from dotenv import load_dotenv

load_dotenv()

THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def query_threatfox(days: int = 1):
    print(f"Here ate query_threatfox()")
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    if THREATFOX_API_KEY:
        headers["Auth-Key"] = THREATFOX_API_KEY

    payload = {
        "query": "get_iocs",
        "days": days
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        data = response.json()

        if data.get("query_status") != "ok":
            return {"error": "ThreatFox API error", "details": data}

        results = []
        for entry in data.get("data", []):
            if entry["ioc_type"] in ["ip:port", "ip"]:
                ip = entry["ioc"].split(":")[0]
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue

                results.append({
                    "ip": ip,
                    "threat_type": entry.get("threat_type", "Unknown"),
                    "malware": entry.get("malware", "Unknown"),
                    "confidence": entry.get("confidence_level", 0),
                    "tags": entry.get("tags", []),
                    "first_seen": entry.get("first_seen", ""),
                    "last_seen": entry.get("last_seen", ""),
                    "source": "ThreatFox"
                })
        return results

    except Exception as e:
        return {"error": f"ThreatFox request failed: {str(e)}"}


def query_abuseip(ip: str):
    print(f"Here at query_abuseip()")
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "Invalid IP address"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "365"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code != 200:
            return {"error": f"AbuseIPDB API error: {response.status_code}", "details": response.text}

        data = response.json()
        if "data" not in data:
            return {"error": "Unexpected AbuseIPDB response", "details": data}

        d = data["data"]
        # print(d)
        return {
            "ip": ip,
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", "Unknown"),
            "usage_type": d.get("usageType", "Unknown"),
            "isp": d.get("isp", "Unknown"),
            "domain": d.get("domain", "Unknown"),
            "total_reports": d.get("totalReports", 0),
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "last_reported": d.get("lastReportedAt", ""),
            "is_public": d.get("isPublic", False),
            "is_whitelisted": d.get("isWhitelisted", False),
            "source": "AbuseIPDB"
        }


    except Exception as e:
        return {"error": f"AbuseIPDB request failed: {str(e)}"}

print(query_abuseip("34.238.45.183"))
print(query_threatfox())