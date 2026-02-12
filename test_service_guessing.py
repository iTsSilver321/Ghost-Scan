import sys
import os

# Ensure we can import from the current directory
sys.path.append(os.getcwd())

from engines.socket_engine import SocketScanner

def test_service_guessing():
    scanner = SocketScanner()
    
    print("Testing Service Guessing Logic...")
    print("-" * 60)
    print(f"{'Port':<6} | {'Banner':<30} | {'Result':<15}")
    print("-" * 60)

    test_cases = [
        (80, "HTTP/1.1 200 OK", "HTTP"),
        (8080, "HTTP/1.1 404 Not Found", "HTTP"),
        (22, "SSH-2.0-OpenSSH_8.2p1", "SSH"),
        (2222, "SSH-2.0-OpenSSH_7.4", "SSH"), # Non-standard port
        (21, "220 (vsFTPd 3.0.3)", "FTP"),
        (2121, "220 (vsFTPd 3.0.3)", "FTP"), # Non-standard port
        (3306, "5.5.5-10.4.11-MariaDB", "MySQL"),
        (6379, "-ERR unknown command", "Redis"),
        (5900, "RFB 003.008", "VNC"),
    ]
    
    passed = 0
    failed = 0
    for port, banner, expected in test_cases:
        actual = scanner._guess_service(port, banner)
        if actual == expected:
            print(f"{port:<6} | {banner[:30]:<30} | PASS")
            passed += 1
        else:
            print(f"{port:<6} | {banner[:30]:<30} | FAIL (Expected {expected}, Got {actual})")
            failed += 1

    print("-" * 60)
    print(f"Passed: {passed}/{len(test_cases)}")
    if failed > 0:
        print(f"FAILED: {failed} test cases.")
        sys.exit(1)

if __name__ == "__main__":
    test_service_guessing()
