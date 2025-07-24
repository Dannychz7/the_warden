#!/usr/bin/env python3
"""
Enhanced diagnostic script to test AbuseIPDB API key and debug response parsing
Save as enhanced_api_test.py
"""

import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

def test_abuseipdb_api_detailed():
    """Test AbuseIPDB API key with detailed response analysis"""
    
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    print("Enhanced AbuseIPDB API Key Test")
    print("=" * 40)
    
    if not api_key:
        print("❌ ERROR: No ABUSEIPDB_API_KEY found in .env file")
        return False
    
    print(f"✓ API key found (length: {len(api_key)} characters)")
    print(f"✓ API key starts with: {api_key[:8]}...")
    
    # Test with the known malicious IP
    test_ip = "34.238.45.183"
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": test_ip,
        "maxAgeInDays": "90",  # Increased from 30 to get more historical data
        "verbose": ""  # Request verbose output for more details
    }
    
    print(f"\nTesting with IP: {test_ip}")
    print(f"Request URL: {url}")
    print(f"Headers: {headers}")
    print(f"Parameters: {params}")
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        print(f"\nResponse status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 401:
            print("❌ ERROR: Invalid API key!")
            return False
        elif response.status_code == 429:
            print("❌ ERROR: Rate limit exceeded!")
            return False
        elif response.status_code != 200:
            print(f"❌ ERROR: HTTP {response.status_code}")
            print(f"Response text: {response.text}")
            return False
        
        # Print raw response for debugging
        print(f"\n📋 Raw JSON Response:")
        print("-" * 50)
        raw_response = response.text
        print(raw_response)
        print("-" * 50)
        
        # Parse response
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            print(f"❌ ERROR: Failed to parse JSON: {e}")
            return False
        
        print(f"\n📊 Parsed Response Structure:")
        print(json.dumps(data, indent=2))
        
        if "data" not in data:
            print(f"❌ ERROR: Missing 'data' field in response")
            return False
        
        result = data["data"]
        
        # Extract all available fields
        ip_address = result.get("ipAddress", "N/A")
        is_public = result.get("isPublic", "N/A")
        ip_version = result.get("ipVersion", "N/A")
        is_whitelisted = result.get("isWhitelisted", "N/A")
        confidence = result.get("abuseConfidencePercentage", 0)
        country_code = result.get("countryCode", "N/A")
        country_name = result.get("countryName", "N/A")
        usage_type = result.get("usageType", "N/A")
        isp = result.get("isp", "N/A")
        domain = result.get("domain", "N/A")
        total_reports = result.get("totalReports", 0)
        num_distinct_users = result.get("numDistinctUsers", 0)
        last_reported = result.get("lastReportedAt", "N/A")
        
        print("\n✅ SUCCESS! API Response Received")
        print("=" * 40)
        print(f"IP Address: {ip_address}")
        print(f"Is Public: {is_public}")
        print(f"IP Version: {ip_version}")
        print(f"Is Whitelisted: {is_whitelisted}")
        print(f"🚨 Abuse Confidence: {confidence}%")
        print(f"📊 Total Reports: {total_reports}")
        print(f"👥 Distinct Reporters: {num_distinct_users}")
        print(f"🌍 Country: {country_name} ({country_code})")
        print(f"🏢 ISP: {isp}")
        print(f"🌐 Domain: {domain}")
        print(f"🏷️  Usage Type: {usage_type}")
        print(f"⏰ Last Reported: {last_reported}")
        
        # Check for reports array (verbose mode)
        if "reports" in result:
            reports = result["reports"]
            print(f"\n📝 Recent Reports ({len(reports)} shown):")
            for i, report in enumerate(reports[:3]):  # Show first 3 reports
                reported_at = report.get("reportedAt", "N/A")
                comment = report.get("comment", "No comment")[:100] + "..." if len(report.get("comment", "")) > 100 else report.get("comment", "No comment")
                categories = report.get("categories", [])
                print(f"  Report {i+1}: {reported_at}")
                print(f"    Categories: {categories}")
                print(f"    Comment: {comment}")
        
        # Analysis
        print("\n🔍 Analysis:")
        if confidence >= 75:
            print(f"   🚨 HIGH THREAT - {confidence}% confidence with {total_reports} reports")
        elif confidence >= 25:
            print(f"   ⚠️  MEDIUM THREAT - {confidence}% confidence with {total_reports} reports")
        elif confidence > 0:
            print(f"   ⚡ LOW THREAT - {confidence}% confidence with {total_reports} reports")
        else:
            print(f"   ✅ CLEAN - No abuse confidence, but {total_reports} reports exist")
            if total_reports > 0:
                print(f"      🤔 NOTE: {total_reports} reports exist but 0% confidence is unusual")
                print(f"           This might indicate old/expired reports or false positives")
        
        return True
        
    except requests.exceptions.Timeout:
        print("❌ ERROR: Request timeout")
        return False
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Connection failed")
        return False
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return False

def compare_with_known_good_ip():
    """Test with a known clean IP for comparison"""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    print("\n🔍 Testing with Known Clean IP (Google DNS)")
    print("=" * 40)
    
    clean_ip = "8.8.8.8"  # Google's public DNS - should be clean
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": clean_ip,
        "maxAgeInDays": "90"
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            result = data["data"]
            confidence = result.get("abuseConfidencePercentage", 0)
            reports = result.get("totalReports", 0)
            
            print(f"Clean IP Test ({clean_ip}):")
            print(f"  Confidence: {confidence}%")
            print(f"  Reports: {reports}")
            
            if confidence == 0:
                print("  ✅ Clean IP shows 0% as expected")
            else:
                print(f"  ⚠️  Even clean IP shows {confidence}% - API might be working correctly")
                
    except Exception as e:
        print(f"Clean IP test failed: {e}")

if __name__ == "__main__":
    print("🔍 Enhanced AbuseIPDB API Diagnostic\n")
    
    # Main test
    success = test_abuseipdb_api_detailed()
    
    if success:
        # Compare with clean IP
        compare_with_known_good_ip()
    
    print("\n" + "=" * 60)
    print("🎯 DEBUGGING RECOMMENDATIONS")
    print("=" * 60)
    
    if success:
        print("✅ API is working - Check the raw response above")
        print("   • Look for discrepancies in the parsed vs expected data")
        print("   • Check if maxAgeInDays parameter affects results")
        print("   • Verify your MCP server is using the same API endpoint")
        print("   • Consider that AbuseIPDB data can change over time")
    else:
        print("❌ API test failed - Fix the connection issues first")
    
    print("\n📋 Next Steps:")
    print("   1. Compare raw JSON response with expected values")
    print("   2. Check if your MCP server uses different parameters")
    print("   3. Verify the IP address hasn't been recently cleaned/updated")
    print("   4. Test with multiple known malicious IPs")