import socket

HOST = "127.0.0.1"
PORT = 9999

def main():
    print("[MCP-Client] Connected to MCP. Type commands like:")
    print("   search: suspicious IP 8.8.8.8")
    print("   tell me about 25.89.123.156")
    print("Type 'exit' or 'quit' to stop.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        while True:
            msg = input(">> ").strip()
            if msg.lower() in {"exit", "quit"}:
                print("[MCP-Client] Exiting.")
                break

            try:
                s.sendall(msg.encode())
                data = s.recv(8192).decode()

                if not data:
                    print("[MCP-Client] No response received.")
                    continue

                print("\n[Response From MCP]:")
                print(data.strip())
                print()

            except Exception as e:
                print(f"[MCP-Client] Error: {e}")

if __name__ == "__main__":
    main()
