import ctypes
import os
from typing import List, Dict, Any
from .base import ScannerEngine
from .socket_engine import SocketScanner 

# Define C structures
class PortResult(ctypes.Structure):
    _fields_ = [("port", ctypes.c_uint16),
                ("is_open", ctypes.c_bool),
                ("banner", ctypes.c_char_p)] # New field

class ScanResultArgs(ctypes.Structure):
    _fields_ = [("results", ctypes.POINTER(PortResult)),
                ("len", ctypes.c_size_t)]

class RustScanner(ScannerEngine):
    """
    Implementation of ScannerEngine using the high-performance Rust core.
    """
    
    def __init__(self):
        # Locate the DLL
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dll_path = os.path.join(base_dir, "ghost_core", "target", "release", "ghost_core.dll")
        
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"Rust library not found at {dll_path}. Did you run 'cargo build --release'?")
            
        self.lib = ctypes.CDLL(dll_path)
        
        # Define function signatures
        self.lib.scan_target.argtypes = [
            ctypes.c_char_p,          # target_ip
            ctypes.POINTER(ctypes.c_uint16), # ports array
            ctypes.c_size_t,          # ports_len
            ctypes.c_size_t,          # threads
            ctypes.c_uint64           # timeout_ms
        ]
        self.lib.scan_target.restype = ctypes.POINTER(ScanResultArgs)
        
        self.lib.free_scan_results.argtypes = [ctypes.POINTER(ScanResultArgs)]
        self.lib.free_scan_results.restype = None

    def scan(self, target: str, ports: List[int], threads: int, timeout: float) -> List[Dict[str, Any]]:
        # 1. Prepare inputs
        target_bytes = target.encode('utf-8')
        ports_array = (ctypes.c_uint16 * len(ports))(*ports)
        timeout_ms = int(timeout * 1000)
        
        # 2. Call Rust function
        res_ptr = self.lib.scan_target(
            target_bytes,
            ports_array,
            len(ports),
            threads,
            timeout_ms
        )
        
        if not res_ptr:
            return [{"error": "Rust scanner returned null pointer (check target validity)"}]
            
        try:
            # 3. Process results
            results = []
            args = res_ptr.contents
            
            scan_results = args.results
            for i in range(args.len):
                res = scan_results[i]
                if res.is_open:
                    banner = "Unknown"
                    if res.banner:
                        try:
                            banner = res.banner.decode('utf-8', errors='ignore')
                        except:
                            pass
                    
                    service = self._guess_service(res.port, banner)

                    results.append({
                        "port": res.port,
                        "status": "OPEN",
                        "service": service,
                        "banner": banner
                    })
            
            return sorted(results, key=lambda x: x['port'])
            
        finally:
            # 4. Free memory
            self.lib.free_scan_results(res_ptr)

    def _guess_service(self, port: int, banner: str) -> str:
        # Reusing the simple guessing logic or import it
        # For now, let's just duplicate the simple map for speed/independence
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
            53: "DNS", 80: "HTTP", 443: "HTTPS", 
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 
            6379: "Redis", 8080: "HTTP-Alt"
        }
        if port in common_ports: return common_ports[port]
        return "Unknown"
