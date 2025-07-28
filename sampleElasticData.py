#!/usr/bin/env python3
"""
Elasticsearch Security Logs Generator
Simulates security events across VPN, authentication, system info, and server monitoring
"""

import json
import random
import datetime
import uuid
import requests
import time
import os
from typing import Dict, List, Tuple

# Constants
ELASTICSEARCH_URL = "http://192.168.1.222:5000"
INDEX1 = "logs-signins"
INDEX2 = "logs-vpn"
INDEX3 = "logs-sysinfo"
INDEX4 = "logs-prdservers"
INDEX5 = "logs-devicelogs"

# Malicious IP addresses from abuseIPdb
MALICIOUS_IPS = [
    "175.152.32.105", "82.157.190.174", "202.39.251.216", "167.94.146.49",
    "156.249.63.153", "45.202.78.66", "65.49.1.162", "64.225.72.98",
    "162.142.125.135", "219.99.208.166", "8.211.199.38", "203.2.164.205",
    "180.49.172.235", "8.209.211.125", "125.41.243.196", "89.44.137.176",
    "121.179.94.187", "81.89.212.67", "87.106.188.106", "195.178.110.160"
]

# Employee data pool
EMPLOYEES = [
    {"username": "john.smith", "full_name": "John Smith", "department": "Engineering", "role": "Senior Developer"},
    {"username": "sarah.johnson", "full_name": "Sarah Johnson", "department": "Security", "role": "Security Analyst"},
    {"username": "mike.davis", "full_name": "Mike Davis", "department": "Operations", "role": "DevOps Engineer"},
    {"username": "emily.wilson", "full_name": "Emily Wilson", "department": "Finance", "role": "Financial Analyst"},
    {"username": "alex.brown", "full_name": "Alex Brown", "department": "Engineering", "role": "Software Engineer"},
    {"username": "lisa.garcia", "full_name": "Lisa Garcia", "department": "HR", "role": "HR Manager"},
    {"username": "david.miller", "full_name": "David Miller", "department": "Sales", "role": "Sales Manager"},
    {"username": "jennifer.taylor", "full_name": "Jennifer Taylor", "department": "Marketing", "role": "Marketing Specialist"},
    {"username": "robert.anderson", "full_name": "Robert Anderson", "department": "Engineering", "role": "Lead Architect"},
    {"username": "amanda.thomas", "full_name": "Amanda Thomas", "department": "Operations", "role": "System Administrator"},
    {"username": "chris.jackson", "full_name": "Chris Jackson", "department": "Security", "role": "CISO"},
    {"username": "michelle.white", "full_name": "Michelle White", "department": "Legal", "role": "Legal Counsel"},
    {"username": "james.harris", "full_name": "James Harris", "department": "Engineering", "role": "Backend Developer"},
    {"username": "natalie.martin", "full_name": "Natalie Martin", "department": "Product", "role": "Product Manager"},
    {"username": "kevin.lee", "full_name": "Kevin Lee", "department": "Finance", "role": "Controller"}
]

# Sample data for realistic generation
CITIES_COUNTRIES = [
    ("New York", "US", "NY", "10001"), ("London", "GB", "ENG", "SW1A"),
    ("Tokyo", "JP", "13", "100-0001"), ("Sydney", "AU", "NSW", "2000"),
    ("Toronto", "CA", "ON", "M5H"), ("Berlin", "DE", "BE", "10115"),
    ("Paris", "FR", "IDF", "75001"), ("Singapore", "SG", "01", "018989"),
    ("Mumbai", "IN", "MH", "400001"), ("São Paulo", "BR", "SP", "01310-100")
]

OPERATING_SYSTEMS = ["Windows 11", "Windows 10", "macOS Sonoma", "Ubuntu 22.04", "CentOS 8", "Red Hat 9"]
DEVICE_TYPES = ["Laptop", "Desktop", "Mobile", "Tablet"]
BROWSERS = ["Chrome", "Firefox", "Safari", "Edge"]
VPN_PROTOCOLS = ["OpenVPN", "IKEv2", "WireGuard", "L2TP"]

MALICIOUS_PROCESSES = [
    "mimikatz.exe", "psexec.exe", "nc.exe", "powershell -enc", "cmd.exe /c whoami",
    "net user administrator", "reg add HKLM", "schtasks /create", "wmic process",
    "netsh advfirewall", "vssadmin delete shadows", "bcdedit /set", "certutil -urlcache"
]

NORMAL_PROCESSES = [
    "explorer.exe", "chrome.exe", "firefox.exe", "notepad.exe", "outlook.exe",
    "teams.exe", "slack.exe", "code.exe", "python.exe", "java.exe", "docker.exe",
    "kubectl", "git.exe", "npm.exe", "node.exe", "ssh.exe"
]

SUSPICIOUS_COMMANDS = [
    "sudo su -", "chmod 777", "rm -rf /", "cat /etc/passwd", "history -c",
    "unset HISTFILE", "nohup", "base64 -d", "curl | sh", "wget -O-"
]

def is_malicious():
    """Determines if a log is malicious based on a 1% chance."""
    return random.randint(1, 100) > 50

def generate_ip():
    """Generate a random public IP address."""
    return f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def generate_internal_ip():
    """Generate a random internal IP address."""
    networks = ["192.168", "10.0", "172.16"]
    network = random.choice(networks)
    return f"{network}.{random.randint(1, 255)}.{random.randint(1, 254)}"

def generate_mac_address():
    """Generate a random MAC address."""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def get_timestamp_sequence(base_time=None):
    """Generate a sequence of timestamps for correlated events."""
    if base_time is None:
        base_time = datetime.datetime.now()
    
    timestamps = []
    for i in range(5):  # 5 different log types
        offset = random.randint(1, 60)  # 1-60 seconds apart
        timestamps.append(base_time + datetime.timedelta(seconds=i * offset))
    
    return timestamps

def create_elasticsearch_indices():
    """Create Elasticsearch indices with explicit mappings."""
    
    # Mapping for logs-signins
    signin_mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "username": {"type": "keyword"},
                "full_name": {"type": "text"},
                "department": {"type": "keyword"},
                "role": {"type": "keyword"},
                "service": {"type": "keyword"},
                "authentication_method": {"type": "keyword"},
                "mfa_status": {"type": "keyword"},
                "status": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "user_agent": {"type": "text"},
                "browser": {"type": "keyword"},
                "session_id": {"type": "keyword"},
                "correlation_id": {"type": "keyword"},
                "risk_score": {"type": "integer"},
                "failure_reason": {"type": "text"},
                "is_malicious": {"type": "boolean"}
            }
        }
    }
    
    # Mapping for logs-vpn
    vpn_mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "username": {"type": "keyword"},
                "external_ip": {"type": "ip"},
                "internal_ip": {"type": "ip"},
                "city": {"type": "keyword"},
                "country": {"type": "keyword"},
                "state": {"type": "keyword"},
                "zip_code": {"type": "keyword"},
                "latitude": {"type": "float"},
                "longitude": {"type": "float"},
                "vpn_protocol": {"type": "keyword"},
                "vpn_server": {"type": "keyword"},
                "status": {"type": "keyword"},
                "bytes_sent": {"type": "long"},
                "bytes_received": {"type": "long"},
                "session_duration": {"type": "integer"},
                "correlation_id": {"type": "keyword"},
                "is_malicious": {"type": "boolean"}
            }
        }
    }
    
    # Mapping for logs-sysinfo
    sysinfo_mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "username": {"type": "keyword"},
                "device_id": {"type": "keyword"},
                "mac_address": {"type": "keyword"},
                "ip_address": {"type": "ip"},
                "internal_ip": {"type": "ip"},
                "operating_system": {"type": "keyword"},
                "device_type": {"type": "keyword"},
                "device_name": {"type": "keyword"},
                "browser": {"type": "keyword"},
                "browser_version": {"type": "keyword"},
                "screen_resolution": {"type": "keyword"},
                "timezone": {"type": "keyword"},
                "last_seen": {"type": "date"},
                "compliance_status": {"type": "keyword"},
                "antivirus_status": {"type": "keyword"},
                "correlation_id": {"type": "keyword"},
                "is_malicious": {"type": "boolean"}
            }
        }
    }
    
    # Mapping for logs-prdservers
    prdservers_mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "username": {"type": "keyword"},
                "server_name": {"type": "keyword"},
                "server_ip": {"type": "ip"},
                "login_time": {"type": "date"},
                "session_duration": {"type": "integer"},
                "login_method": {"type": "keyword"},
                "processes_running": {"type": "text"},
                "cpu_usage": {"type": "float"},
                "memory_usage": {"type": "float"},
                "disk_usage": {"type": "float"},
                "network_connections": {"type": "integer"},
                "privilege_level": {"type": "keyword"},
                "commands_executed": {"type": "text"},
                "correlation_id": {"type": "keyword"},
                "is_malicious": {"type": "boolean"}
            }
        }
    }
    
    # Mapping for logs-devicelogs
    devicelogs_mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "server_name": {"type": "keyword"},
                "server_ip": {"type": "ip"},
                "process_name": {"type": "keyword"},
                "process_id": {"type": "integer"},
                "parent_process_id": {"type": "integer"},
                "user": {"type": "keyword"},
                "action": {"type": "keyword"},
                "command_line": {"type": "text"},
                "file_path": {"type": "keyword"},
                "registry_key": {"type": "keyword"},
                "network_connection": {"type": "text"},
                "hash": {"type": "keyword"},
                "signature_status": {"type": "keyword"},
                "correlation_id": {"type": "keyword"},
                "is_malicious": {"type": "boolean"}
            }
        }
    }
    
    indices = [
        (INDEX1, signin_mapping),
        (INDEX2, vpn_mapping),
        (INDEX3, sysinfo_mapping),
        (INDEX4, prdservers_mapping),
        (INDEX5, devicelogs_mapping)
    ]
    
    for index_name, mapping in indices:
        try:
            # Check if index exists
            check_response = requests.head(f"{ELASTICSEARCH_URL}/{index_name}")
            
            if check_response.status_code == 200:
                print(f"⚡ Index {index_name} already exists, skipping creation")
                continue
            
            # Create index with mapping (only if it doesn't exist)
            response = requests.put(f"{ELASTICSEARCH_URL}/{index_name}", 
                                  json=mapping, 
                                  headers={'Content-Type': 'application/json'})
            
            if response.status_code in [200, 201]:
                print(f"✓ Created index: {index_name}")
            else:
                print(f"✗ Failed to create index {index_name}: {response.text}")
                
        except Exception as e:
            print(f"✗ Error creating index {index_name}: {e}")

def createSigninData(employee: Dict, timestamp: datetime.datetime, correlation_id: str, malicious: bool = False) -> Dict:
    """Generate signin log data."""
    
    services = ["VPN", "Office365", "AWS Console", "Azure Portal", "Internal App"]
    auth_methods = ["Password", "MFA", "SSO", "Certificate"]
    browsers = ["Chrome/91.0", "Firefox/89.0", "Safari/14.1", "Edge/91.0"]
    
    if malicious:
        # Malicious signin patterns
        status = random.choice(["failed", "failed", "failed", "success"])  # Multiple failures then success
        source_ip = random.choice(MALICIOUS_IPS)
        risk_score = random.randint(80, 100)
        mfa_status = "bypassed" if status == "success" else "failed"
        failure_reason = random.choice([
            "Invalid password", "Account locked", "MFA timeout", 
            "Suspicious location", "Too many attempts"
        ]) if status == "failed" else None
    else:
        status = random.choice(["success", "success", "success", "failed"])  # Mostly successful
        source_ip = generate_ip()
        risk_score = random.randint(1, 30)
        mfa_status = "success" if status == "success" else "failed"
        failure_reason = "Invalid password" if status == "failed" else None
    
    return {
        "@timestamp": timestamp.isoformat(),
        "username": employee["username"],
        "full_name": employee["full_name"],
        "department": employee["department"],
        "role": employee["role"],
        "service": random.choice(services),
        "authentication_method": random.choice(auth_methods),
        "mfa_status": mfa_status,
        "status": status,
        "source_ip": source_ip,
        "user_agent": f"Mozilla/5.0 ({random.choice(['Windows NT 10.0', 'Macintosh', 'X11; Linux x86_64'])}) AppleWebKit/537.36",
        "browser": random.choice(browsers),
        "session_id": str(uuid.uuid4()),
        "correlation_id": correlation_id,
        "risk_score": risk_score,
        "failure_reason": failure_reason,
        "is_malicious": malicious
    }

def createVpnData(employee: Dict, timestamp: datetime.datetime, correlation_id: str, malicious: bool = False) -> Dict:
    """Generate VPN log data."""
    
    if malicious:
        external_ip = random.choice(MALICIOUS_IPS)
        city, country, state, zip_code = random.choice([
            ("Unknown", "CN", "Unknown", "000000"),
            ("Tor Exit", "XX", "Unknown", "000000"),
            ("Moscow", "RU", "MOW", "101000")
        ])
        status = "success"  # Successful after multiple attempts
        session_duration = random.randint(3600, 7200)  # Long sessions
    else:
        external_ip = generate_ip()
        city, country, state, zip_code = random.choice(CITIES_COUNTRIES)
        status = random.choice(["success", "success", "success", "failed"])
        session_duration = random.randint(300, 3600)
    
    return {
        "@timestamp": timestamp.isoformat(),
        "username": employee["username"],
        "external_ip": external_ip,
        "internal_ip": generate_internal_ip(),
        "city": city,
        "country": country,
        "state": state,
        "zip_code": zip_code,
        "latitude": round(random.uniform(-90, 90), 6),
        "longitude": round(random.uniform(-180, 180), 6),
        "vpn_protocol": random.choice(VPN_PROTOCOLS),
        "vpn_server": f"vpn-{random.choice(['us', 'eu', 'asia'])}-{random.randint(1, 10)}.company.com",
        "status": status,
        "bytes_sent": random.randint(1000000, 100000000),
        "bytes_received": random.randint(5000000, 500000000),
        "session_duration": session_duration,
        "correlation_id": correlation_id,
        "is_malicious": malicious
    }

def createSysInfoData(employee: Dict, timestamp: datetime.datetime, correlation_id: str, malicious: bool = False) -> Dict:
    """Generate system info log data."""
    
    if malicious:
        operating_system = random.choice(["Windows 7", "Unknown OS", "Linux Custom"])
        compliance_status = "non-compliant"
        antivirus_status = "disabled"
    else:
        operating_system = random.choice(OPERATING_SYSTEMS)
        compliance_status = random.choice(["compliant", "compliant", "non-compliant"])
        antivirus_status = random.choice(["active", "active", "disabled"])
    
    return {
        "@timestamp": timestamp.isoformat(),
        "username": employee["username"],
        "device_id": str(uuid.uuid4()),
        "mac_address": generate_mac_address(),
        "ip_address": generate_ip(),
        "internal_ip": generate_internal_ip(),
        "operating_system": operating_system,
        "device_type": random.choice(DEVICE_TYPES),
        "device_name": f"{employee['username']}-{random.choice(['laptop', 'desktop', 'mobile'])}",
        "browser": random.choice(BROWSERS),
        "browser_version": f"{random.randint(90, 120)}.0.{random.randint(1000, 9999)}.{random.randint(100, 999)}",
        "screen_resolution": random.choice(["1920x1080", "2560x1440", "3840x2160", "1366x768"]),
        "timezone": random.choice(["UTC-5", "UTC+0", "UTC+9", "UTC-8"]),
        "last_seen": timestamp.isoformat(),
        "compliance_status": compliance_status,
        "antivirus_status": antivirus_status,
        "correlation_id": correlation_id,
        "is_malicious": malicious
    }

def createPrdServersData(employee: Dict, timestamp: datetime.datetime, correlation_id: str, malicious: bool = False) -> Dict:
    """Generate production server log data."""
    
    servers = ["prd-web-01", "prd-db-01", "prd-api-01", "prd-cache-01", "prd-queue-01"]
    login_methods = ["SSH", "RDP", "Console", "Web Terminal"]
    
    if malicious:
        processes_running = random.choice(MALICIOUS_PROCESSES)
        commands_executed = random.choice(SUSPICIOUS_COMMANDS)
        privilege_level = "administrator"
        cpu_usage = random.uniform(80, 100)
        session_duration = random.randint(7200, 14400)  # Long sessions
    else:
        processes_running = random.choice(NORMAL_PROCESSES)
        commands_executed = random.choice(["ls -la", "ps aux", "top", "df -h", "netstat -an"])
        privilege_level = random.choice(["user", "user", "administrator"])
        cpu_usage = random.uniform(5, 50)
        session_duration = random.randint(600, 3600)
    
    return {
        "@timestamp": timestamp.isoformat(),
        "username": employee["username"],
        "server_name": random.choice(servers),
        "server_ip": generate_internal_ip(),
        "login_time": timestamp.isoformat(),
        "session_duration": session_duration,
        "login_method": random.choice(login_methods),
        "processes_running": processes_running,
        "cpu_usage": round(cpu_usage, 2),
        "memory_usage": round(random.uniform(10, 80), 2),
        "disk_usage": round(random.uniform(20, 90), 2),
        "network_connections": random.randint(5, 50),
        "privilege_level": privilege_level,
        "commands_executed": commands_executed,
        "correlation_id": correlation_id,
        "is_malicious": malicious
    }

def createDeviceLogsData(timestamp: datetime.datetime, correlation_id: str, malicious: bool = False) -> Dict:
    """Generate device monitoring log data."""
    
    servers = ["prd-web-01", "prd-db-01", "prd-api-01", "prd-cache-01", "prd-queue-01"]
    actions = ["start", "stop", "create", "modify", "delete", "network_connect"]
    
    if malicious:
        process_name = random.choice(MALICIOUS_PROCESSES)
        command_line = random.choice([
            "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden",
            "cmd.exe /c echo malicious > temp.txt",
            "nc.exe -l -p 4444 -e cmd.exe",
            "mimikatz.exe sekurlsa::logonpasswords"
        ])
        signature_status = "unsigned"
        user = "SYSTEM"
    else:
        process_name = random.choice(NORMAL_PROCESSES)
        command_line = f"{process_name} --config /etc/config.conf"
        signature_status = random.choice(["signed", "signed", "unsigned"])
        user = random.choice(EMPLOYEES)["username"]
    
    return {
        "@timestamp": timestamp.isoformat(),
        "server_name": random.choice(servers),
        "server_ip": generate_internal_ip(),
        "process_name": process_name,
        "process_id": random.randint(1000, 99999),
        "parent_process_id": random.randint(100, 9999),
        "user": user,
        "action": random.choice(actions),
        "command_line": command_line,
        "file_path": f"/opt/app/{process_name}",
        "registry_key": f"HKLM\\SOFTWARE\\Company\\{process_name}" if "Windows" in random.choice(OPERATING_SYSTEMS) else None,
        "network_connection": f"{generate_internal_ip()}:443" if random.choice([True, False]) else None,
        "hash": f"sha256:{uuid.uuid4().hex}",
        "signature_status": signature_status,
        "correlation_id": correlation_id,
        "is_malicious": malicious
    }

def save_to_jsonl(data: List[Dict], filename: str):
    """Save data to JSON Lines format."""
    os.makedirs("logs", exist_ok=True)
    filepath = f"logs/{filename}"
    
    with open(filepath, 'w') as f:
        for record in data:
            f.write(json.dumps(record) + '\n')
    
    print(f"✓ Saved {len(data)} records to {filepath}")

def send_to_elasticsearch(index: str, data: List[Dict]):
    """Send data to Elasticsearch using bulk API."""
    if not data:
        return
    
    # Prepare bulk request
    bulk_data = []
    for record in data:
        bulk_data.append(json.dumps({"index": {"_index": index}}))
        bulk_data.append(json.dumps(record))
    
    bulk_body = '\n'.join(bulk_data) + '\n'
    
    try:
        response = requests.post(
            f"{ELASTICSEARCH_URL}/_bulk",
            data=bulk_body,
            headers={'Content-Type': 'application/x-ndjson'}
        )
        
        if response.status_code == 200:
            result = response.json()
            errors = [item for item in result.get('items', []) if 'error' in item.get('index', {})]
            if errors:
                print(f"✗ Bulk insert errors for {index}: {len(errors)} failed")
            else:
                print(f"✓ Successfully sent {len(data)} records to {index}")
        else:
            print(f"✗ Failed to send to {index}: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"✗ Error sending to {index}: {e}")

def simulate_user_activity(external_ip: str = None):
    """Simulate a complete user activity flow across all log sources."""
    
    # Select 3 random employees
    selected_employees = random.sample(EMPLOYEES, 3)
    
    for employee in selected_employees:
        # Generate correlation ID for this user session
        correlation_id = str(uuid.uuid4())
        
        # Determine if this session is malicious
        malicious = is_malicious()
        
        # Generate correlated timestamps
        base_time = datetime.datetime.now() - datetime.timedelta(
            minutes=random.randint(1, 60)
        )
        timestamps = get_timestamp_sequence(base_time)
        
        print(f"\n{'='*50}")
        print(f"Simulating activity for: {employee['full_name']} ({employee['username']})")
        print(f"Session ID: {correlation_id}")
        print(f"Malicious: {'YES' if malicious else 'NO'}")
        print(f"{'='*50}")
        
        all_logs = {
            INDEX2: [],  # VPN first
            INDEX1: [],  # Then signin
            INDEX3: [],  # Then sysinfo
            INDEX4: [],  # Then prd servers
            INDEX5: []   # Finally device logs
        }
        
        # If malicious, simulate brute force with multiple failed attempts
        if malicious:
            print("🚨 Simulating brute force attack pattern...")
            
            # Generate 10+ failed attempts before success
            failed_attempts = random.randint(10, 15)
            
            for attempt in range(failed_attempts):
                failed_timestamp = base_time - datetime.timedelta(seconds=attempt * 30)
                
                # Failed VPN attempts
                failed_vpn = createVpnData(employee, failed_timestamp, correlation_id, True)
                failed_vpn["status"] = "failed"
                all_logs[INDEX2].append(failed_vpn)
                
                # Failed signin attempts
                failed_signin = createSigninData(employee, failed_timestamp, correlation_id, True)
                failed_signin["status"] = "failed"
                all_logs[INDEX1].append(failed_signin)
        
        # Generate successful login sequence
        vpn_log = createVpnData(employee, timestamps[0], correlation_id, malicious)
        if external_ip:
            vpn_log["external_ip"] = external_ip
        all_logs[INDEX2].append(vpn_log)
        
        signin_log = createSigninData(employee, timestamps[1], correlation_id, malicious)
        all_logs[INDEX1].append(signin_log)
        
        sysinfo_log = createSysInfoData(employee, timestamps[2], correlation_id, malicious)
        all_logs[INDEX3].append(sysinfo_log)
        
        prd_log = createPrdServersData(employee, timestamps[3], correlation_id, malicious)
        all_logs[INDEX4].append(prd_log)
        
        device_log = createDeviceLogsData(timestamps[4], correlation_id, malicious)
        all_logs[INDEX5].append(device_log)
        
        # Save and send logs for each index
        for index, logs in all_logs.items():
            if logs:
                filename = f"{index}_{correlation_id[:8]}.jsonl"
                save_to_jsonl(logs, filename)
                send_to_elasticsearch(index, logs)
        
        print(f"✓ Completed simulation for {employee['username']}")
        time.sleep(1)  # Small delay between users

def main():
    """Main function to orchestrate the logging simulation."""
    print("🚀 Starting Elasticsearch Security Logs Generator")
    print(f"Target Elasticsearch: {ELASTICSEARCH_URL}")
    
    # Test Elasticsearch connection
    try:
        response = requests.get(ELASTICSEARCH_URL)
        if response.status_code == 200:
            cluster_info = response.json()
            print(f"✓ Connected to Elasticsearch cluster: {cluster_info.get('cluster_name')}")
        else:
            print("✗ Failed to connect to Elasticsearch")
            return
    except Exception as e:
        print(f"✗ Cannot connect to Elasticsearch: {e}")
        return
    
    # Create indices
    print("\n📋 Creating Elasticsearch indices...")
    create_elasticsearch_indices()
    
    # Get external IP from user
    external_ip = input("\n🌐 Enter external IP (or press Enter for random): ").strip()
    if not external_ip:
        external_ip = None
        print("Using random external IPs")
    else:
        print(f"Using external IP: {external_ip}")
    
    # Start simulation
    print("\n🎭 Starting user activity simulation...")
    simulate_user_activity(external_ip)
    
    print(f"\n🎉 Simulation complete! Check your Elasticsearch indices:")
    for index in [INDEX1, INDEX2, INDEX3, INDEX4, INDEX5]:
        print(f"   - {index}")
    
    print(f"\n📊 Query example:")
    print(f"curl -X GET '{ELASTICSEARCH_URL}/{INDEX1}/_search?pretty&q=is_malicious:true'")

if __name__ == "__main__":
    main()