import socket
import concurrent.futures
from typing import List, Dict, Any
from .base import ScannerEngine

class SocketScanner(ScannerEngine):
    """
    Implementation of ScannerEngine using Python's standard socket library.
    Performs a TCP Connect Scan.
    """

    def scan(self, target: str, ports: List[int], threads: int, timeout: float) -> List[Dict[str, Any]]:
        results = []
        # We resolve the hostname once to avoid repeated DNS lookups
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return [{"error": f"Could not resolve hostname: {target}"}]

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            # Map each port to a future
            future_to_port = {
                executor.submit(self._scan_port, target_ip, port, timeout): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result: # Only append if we got a result (open port)
                        results.append(result)
                except Exception as exc:
                    print(f'Port {port} generated an exception: {exc}')
        
        return sorted(results, key=lambda x: x['port'])

    def _scan_port(self, ip: str, port: int, timeout: float) -> Dict[str, Any]:
        """
        Scans a single port.
        Returns a dictionary if open, None if closed/filtered.
        """
        try:
            # Create a socket object
            # AF_INET = IPv4, SOCK_STREAM = TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                
                # attempt to connect
                result = s.connect_ex((ip, port))
                
                if result == 0:
                    # Connection successful (Open)
                    banner = self._grab_banner(s)
                    service = self._guess_service(port, banner)
                    return {
                        "port": port,
                        "status": "OPEN",
                        "service": service,
                        "banner": banner
                    }
                else:
                    # Connection failed (Closed or Filtered)
                    # For a simple connect scan, we treat everything non-zero as closed/filtered
                    # connect_ex returns errno.
                    return None
                    
        except socket.error:
            return None

    def _grab_banner(self, sock: socket.socket) -> str:
        """
        Attempts to grab a banner from the connected socket.
        """
        try:
            # Send a generic query to provoke a response if the server is quiet
            # Some servers (like HTTP) wait for the client to speak first.
            # Others (like SSH, FTP) send a banner immediately.
            
            # We'll try to peek first to see if there's data waiting
            # But standard sockets don't have a reliable cross-platform 'peek' that doesn't block
            # effectively without polling.
            
            # Strategy:
            # 1. Try to receive immediately (for chatty protocols like SSH)
            # 2. If timeout, try sending a generic byte and receiving again
            
            sock.settimeout(1.0) # Short timeout for banner grabbing
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner
            except socket.timeout:
                pass # No immediate greeting
            
            # Try sending a probe
            sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
            except socket.timeout:
                return "Unknown" # No response to probe either
                
        except Exception:
            return "Unknown"

    def _guess_service(self, port: int, banner: str) -> str:
        """
        Simple service guessing based on port and banner.
        """
        # Common ports
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Alt"
        }
        
        if port in common_ports:
            return common_ports[port]
            
        return "Unknown"
