# test_client.py
import socket

HOST = "127.0.0.1"
PORT = 9999

print("[MCP-Client] Type commands like `search: suspicious IP` or anything else.")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        msg = input(">> ").strip()
        if msg.lower() in {"exit", "quit"}:
            break
        s.sendall(msg.encode())
        data = s.recv(4096).decode()
        print("\n[MCP-LLM]:", data.strip(), "\n")
