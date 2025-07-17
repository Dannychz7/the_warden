# mcp_server.py
import socket
from llm_client import query_llm
from tools.intel_providers import query_abuseip, query_threatfox
import json

HOST = "127.0.0.1"
PORT = 9999

def handle_command(raw_msg: str) -> str:
    if raw_msg.lower() == "threatfox":
        data = query_threatfox()
        # print(json.dumps(data, indent=2))
        prompt = f"Summarize the recent threat indicators from ThreatFox:\n{json.dumps(data[:3], indent=2)}"
        return query_llm(prompt)
    elif raw_msg.lower().startswith("ip "):
        try:
            # Extract the IP address after the "ip " command
            ip_address = raw_msg.split(" ", 1)[1].strip()
            data = query_abuseip(ip_address)

            if not data:
                return ("No data returned from AbuseIPDB.")
            else:
                # print(f"Here is the data from AbuseIPDB for {ip_address}: {data}")
                summary_input = json.dumps(data, indent=2)
                prompt = f"Summarize this info from Abuse IP DB:\n{summary_input}"
                return query_llm(prompt)
        except Exception as e:
            print(f"Error handling IP query: {e}")
    else:
        return query_llm(raw_msg)

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[MCP] Listening on {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print(f"[MCP] Connected by {addr}")
            while True:
                data = conn.recv(2048).decode().strip()
                if not data:
                    break
                print(f"[MCP] Request: {data}")
                reply = handle_command(data)
                if reply is None:
                    reply = "No data found or error occurred."
                else: 
                    conn.sendall((reply + "\n").encode())

if __name__ == "__main__":
    run_server()