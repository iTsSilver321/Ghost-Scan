from abc import ABC, abstractmethod
from typing import List, Dict, Any

class ScannerEngine(ABC):
    """
    Abstract base class for all scanning engines.
    This allows us to easily swap the underlying engine (System Socket, Raw Socket, Rust FFI)
    while keeping the main interface consistent.
    """

    @abstractmethod
    def scan(self, target: str, ports: List[int], threads: int, timeout: float) -> List[Dict[str, Any]]:
        """
        Scans a list of ports on a target.

        Args:
            target (str): The target IP address or hostname.
            ports (List[int]): A list of port numbers to scan.
            threads (int): The number of concurrent threads to use.
            timeout (float): The timeout in seconds for socket operations.

        Returns:
            List[Dict[str, Any]]: A list of results, where each result is a dictionary
            containing 'port', 'status', 'service', and 'banner'.
        """
        pass
