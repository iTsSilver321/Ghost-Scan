import socket
import re
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

        # Dynamic Banner Timeout
        # If connection timeout is low (local network), we can afford a lower banner timeout
        # but it should still be enough for checking response.
        # Default 1.0s. If timeout < 0.5, we use 0.3s for local speed.
        banner_timeout = 0.3 if timeout < 0.5 else 1.0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            # Map each port to a future
            future_to_port = {
                executor.submit(self._scan_port, target_ip, port, timeout, banner_timeout): port
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

    def _scan_port(self, ip: str, port: int, timeout: float, banner_timeout: float) -> Dict[str, Any]:
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
                    banner = self._grab_banner(s, banner_timeout)
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

    def _grab_banner(self, sock: socket.socket, timeout: float) -> str:
        """
        Attempts to grab a banner from the connected socket.
        """
        try:
            # 1. Very short initial check for "chatty" protocols (SSH, FTP, etc.)
            # These send a banner immediately upon connection.
            initial_wait = min(0.1, timeout / 2)
            sock.settimeout(initial_wait)
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner
            except socket.timeout:
                pass 
            
            # 2. Try sending a probe for "quiet" protocols (HTTP, etc.)
            sock.settimeout(timeout)
            try:
                sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
            except socket.timeout:
                return "Unknown" 
                
        except Exception:
            return "Unknown"

    def _guess_service(self, port: int, banner: str) -> str:
        """
        Simple service guessing based on port and banner.
        """
        # Common ports
        # Regex patterns for banner analysis
        # (Pattern, Service Name)
        service_patterns = [
            (r"^SSH-", "SSH"),
            (r"^HTTP/", "HTTP"),
            (r"^220.*FTP", "FTP"),
            (r"^220.*SMTP", "SMTP"),
            (r"^220.*ESMTP", "SMTP"),
            (r"^\+OK", "POP3"),
            (r"^\* OK", "IMAP"),
            (r"^RFB", "VNC"),
            (r"^-ERR", "Redis"),
            (r"^\+PONG", "Redis"),
            (r"^5\.", "MySQL"), # MySQL often starts with a version number like "5.x.x" or garbage that might contain it upon error/handshake
             # PostgreSQL often sends 'R' for authentication request or 'E' for error, but hard to regex blindly on text decode.
             # We will stick to the safe ones.
        ]

        # 1. Try Regex Matching on Banner
        if banner and banner != "Unknown":
            for pattern, service in service_patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    return service

        # 2. Fallback to Port-based Guessing
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
