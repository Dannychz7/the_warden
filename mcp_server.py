# mcp_server.py
import socket
from llm_client import query_llm
from tools.mock_tools import google_search_mock

HOST = "127.0.0.1"
PORT = 9999

def handle_command(raw_msg: str) -> str:
    if raw_msg.startswith("search:"):
        term = raw_msg.split("search:", 1)[1].strip()
        result = google_search_mock(term)
        prompt = f"A user searched '{term}'. Here is a result: {result}. Summarize or advise."
        return query_llm(prompt)
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
                conn.sendall((reply + "\n").encode())

if __name__ == "__main__":
    run_server()
