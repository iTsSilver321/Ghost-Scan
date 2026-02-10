PRD: "Project Ghost-Scan" (High-Performance Port Scanner)
1. Project Overview
Objective: Develop a CLI-based network reconnaissance tool that identifies active hosts and open ports on a network. The "Vibe": A lightweight, blazingly fast alternative to Nmap, starting with a Python prototype for logic and migrating to Rust for high-concurrency performance.

2. Core Functional Requirements
Phase 1: The Python Prototype (Logic First)
Target Input: Accept single IP addresses, hostnames, or CIDR ranges (e.g., 192.168.1.0/24).

Scanning Engine: Implement a TCP Connect Scan.

Concurrency: Use concurrent.futures or asyncio to scan multiple ports simultaneously (not sequentially).

Service Fingerprinting: For open ports, attempt to grab the "banner" (the initial text response from the service) to identify the software (e.g., "Apache 2.4.41").

Phase 2: The Rust Implementation (Performance)
Efficiency: Use the tokio runtime for asynchronous I/O to handle thousands of socket connections.

Safety: Ensure no memory leaks or thread-safety issues when handling high-speed network packets.

Output: Return results in a clean, structured Table format in the CLI.

3. Technical Specifications
Networking Logic
For each port in the target range, the tool must:

Initiate a TCP Three-Way Handshake.

If the handshake completes (SYN-ACK received), mark the port as OPEN.

If a RST (Reset) packet is received, mark it as CLOSED.

If no response occurs within a defined timeout, mark it as FILTERED (Firewall presence).

Success Metrics
Accuracy: Matches results from nmap -sT.

Speed: Scan 1,000 common ports on a local host in under 2 seconds.

4. User Interface (CLI)
The tool should follow standard security tool syntax: ghostscan --target 192.168.1.1 --ports 1-1000 --threads 50

5. Non-Functional Requirements
Error Handling: Gracefully handle "Permission Denied" errors (raw sockets often require root/admin).

Ethical Guardrail: Display a disclaimer that the tool is for educational/authorized testing purposes only.