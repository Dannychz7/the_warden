# The Warden
# Version: 1.1
The Warden – Local AI SOC Analyst (MCP v0)

Quick‑start + requirements guide to run The Warden on your Mac or Linux workstation.

Developed and tested on a High-spec MacBook Pro M3 Max. Performance will vary on lighter machines; trim model size or use a hosted LLM if needed.

# Setup Timeline
1. Create a Python virtual environment
    - python3 -m venv .venv && source .venv/bin/activate

2. Install dependencies
    - pip install -r requirements.txt
If you want local GGUF inference instead of Ollama, compile with:
    - pip install 'llama-cpp-python[metal]'

3. Pull an LLM with Ollama
    - ollama pull qwen3:8b
Pick any Ollama‑compatible model that fits your hardware and supports reasoning (e.g. Llama‑3‑8B, Phi‑3‑Mini).

4. Smoke‑test the LLM
    - python test_llm.py
The script POSTs to Ollama’s REST endpoint at http://localhost:11434/ and prints the assistant’s reply.

5. Run the minimal MCP server
    - python mcp_server.py
Open another terminal and start the demo client:
    - python test_client.py

Try commands such as:
- search: suspicious domain activity
- what is ThreatFox?
The server will feed your prompt (or the mock Google result) to the LLM, then stream back a SOC‑style advisory.

# UPDATES:
    07/16/25 - Implemented threatFox and abuseIPDB api calls
    07/17/25 - Created Qwen Decsions, allows the AI to call and make decisions
     