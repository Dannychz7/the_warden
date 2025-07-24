import socket
from typing import Optional
from llm_client import handle_input  # move your core input handler here

HOST = "127.0.0.1"
PORT = 9999

def handle_client(conn: socket.socket, addr):
    print(f"[MCP-Server] Connection from {addr}")
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                print(f"[MCP-Server] Connection closed by {addr}")
                break
            user_prompt = data.decode().strip()
            print(f"[MCP-Server] Received: {user_prompt}")
            try:
                response = handle_input(user_prompt)
            except Exception as e:
                response = f"[MCP-Server] Internal error: {e}"
            conn.sendall(response.encode())

def run_server(host: str = HOST, port: int = PORT):
    print(f"[MCP-Server] Listening on {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    run_server()
