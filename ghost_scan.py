import argparse
import sys
import time
import ipaddress
from engines.socket_engine import SocketScanner

# Version and Banner
VERSION = "0.2.0 (Phase 3: Optimization)"
BANNER = r"""
   ______  __  ______  __________     ______________  _  __
  / ____/ / / / / __ \/ ___/_  __/   / ___/ ____/   |/ |/ /
 / / __  / /_/ / / / /\__ \ / /_____ \__ \ /   / /| ||   / 
/ /_/ / / __  / /_/ /___/ // /_____/___/ / /___/ ___ |/   |  
\____/ /_/ /_/\____//____//_/      /____/\____/_/  |_/_/|_|  
                                                             
               Ghost Scan v{VERSION}
"""

def parse_target(target_arg: str) -> list[str]:
    """
    Parses a target string. If CIDR (e.g., 192.168.1.0/24), returns list of IPs.
    Otherwise returns list handling single IP.
    """
    try:
        # Try as CIDR/Network
        network = ipaddress.ip_network(target_arg, strict=False)
        # For single IP input like 192.168.1.1, ip_network returns /32 which has 1 host.
        # But usually users pass just IP. strict=False allows host bits set.
        if network.num_addresses == 1:
             return [str(network.network_address)]
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # Not a CIDR/IP, treat as hostname
        return [target_arg]

def parse_ports(port_arg: str) -> list[int]:
    """
    Parses a port string (e.g., "80", "1-100", "80,443") into a list of integers.
    """
    ports = set()
    parts = port_arg.split(',')
    for part in parts:
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            except ValueError:
                print(f"Invalid port range format: {part}")
                sys.exit(1)
        else:
            try:
                ports.add(int(part))
            except ValueError:
                print(f"Invalid port number: {part}")
                sys.exit(1)
    
    return sorted(list(ports))

def main():
    # Initialize UI Utilities
    from utils.colors import Colors, colorize, print_banner
    from utils.ui import ProgressBar, print_table_header
    
    # Print cool banner
    print_banner("0.3.0")
    
    parser = argparse.ArgumentParser(description="Ghost Scan - A high-performance network reconnaissance tool.")
    parser.add_argument("target", help="Target IP address, hostname, or CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("--ports", "-p", default="1-1000", help="Ports to scan (e.g., 80, 1-1000, 22,80,443)")
    parser.add_argument("--threads", "-t", type=int, default=2000, help="Number of concurrent tasks (default: 2000 for Rust)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    
    parser.add_argument("--engine", "-e", choices=["socket", "rust"], default="rust", help="Scanning engine (default: rust)")
    
    args = parser.parse_args()
    
    # 1. Parse Target
    targets = parse_target(args.target)
    if not targets:
        print(colorize(f"[!] Error: Invalid target specification: {args.target}", Colors.RED))
        sys.exit(1)
        
    print(colorize("-" * 60, Colors.BLUE))
    print(f"{Colors.BOLD}[*] Target:  {args.target} ({len(targets)} hosts){Colors.RESET}")
    print(f"{Colors.BOLD}[*] Ports:   {len(parse_ports('1')) if ',' not in args.ports and '-' not in args.ports else 'Range/List'} ports selected{Colors.RESET}")
    print(f"{Colors.BOLD}[*] Threads: {args.threads}{Colors.RESET}")
    print(f"{Colors.BOLD}[*] Engine:  {args.engine.capitalize()}{Colors.RESET}")
    print(colorize("-" * 60, Colors.BLUE))

    # 2. Parse Ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(colorize(f"\n[!] Error parsing ports: {e}", Colors.RED))
        sys.exit(1)

    # 3. Smart Timeout Optimization
    # If the user didn't specify a custom timeout (still default 1.0),
    # and we are scanning a private network, lower it to 0.2s for speed.
    if args.timeout == 1.0:
        is_private = False
        try:
            # Check the first IP to see if it's private
            if ipaddress.ip_address(targets[0]).is_private:
                is_private = True
        except:
            pass
            
        if is_private:
            print(colorize(f"[*] Local network detected. Optimization: Lowering timeout to 0.2s", Colors.YELLOW))
            args.timeout = 0.2
            
    # 4. Initialize Engine
    scanner = None
    if args.engine == "rust":
        try:
            from engines.rust_engine import RustScanner
            scanner = RustScanner()
        except OSError:
            print(colorize("\n[!] Failed to load Rust engine (ghost_core.dll not found). Falling back to socket engine.", Colors.YELLOW))
            scanner = SocketScanner()
    else:
        scanner = SocketScanner()
        
    start_time = time.time()
    
    # 4. Run Scan (Parallelize over targets)
    all_results = {}
    
    # Limit host concurrency to avoid resource exhaustion
    # If using Rust engine with high threads, we want fewer concurrent hosts
    host_concurrency = 50 if args.engine == "socket" else 10
    
    # Initialize Fingerprinter
    from analyzers.fingerprint import Fingerprinter
    fingerprinter = Fingerprinter()

    import concurrent.futures
    
    print(f"[*] Scanning {len(targets)} hosts with {host_concurrency} workers...")
    
    # Initialize Progress Bar
    progress = ProgressBar(len(targets), prefix='Progress')
    
    def scan_host(ip):
        try:
            res = scanner.scan(ip, ports, args.threads, args.timeout)
            return ip, res
        except Exception as e:
            return ip, [{"error": str(e)}]

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=host_concurrency) as executor:
            future_to_ip = {executor.submit(scan_host, ip): ip for ip in targets}
            
            completed_count = 0
            for future in concurrent.futures.as_completed(future_to_ip):
                ip, results = future.result()
                
                # Update Progress Bar
                progress.increment()
                
                if results and not "error" in results[0] and len(results) > 0:
                     all_results[ip] = results
                elif results and "error" in results[0]:
                     pass
                     
    except KeyboardInterrupt:
        print(colorize("\n\n[!] Scan interrupted by user.", Colors.RED))
        sys.exit(0)
    
    # Ensure progress bar finishes cleanly
    progress.finish()

    end_time = time.time()
    duration = end_time - start_time
    
    print(colorize(f"\nScan completed in {duration:.2f} seconds.", Colors.GREEN))
    
    if not all_results:
        print(colorize("No open ports found or all hosts down.", Colors.YELLOW))
    else:
        for ip, results in all_results.items():
            print(f"\n\n{Colors.BOLD}--- Results for {ip} ---{Colors.RESET}")
            print_table_header()
            
            for res in results:
                if 'error' in res:
                    print(colorize(f"Error: {res['error']}", Colors.RED))
                    continue
                    
                port_str = f"{res['port']}/tcp"
                
                # Sanitize banner: remove newlines and truncate
                raw_banner = res.get('banner', 'Unknown')
                banner_display = raw_banner
                if banner_display:
                    banner_display = banner_display.replace('\n', ' ').replace('\r', ' ')
                    if len(banner_display) > 50:
                        banner_display = banner_display[:47] + "..."
                
                # Analyze fingerprint
                fp = fingerprinter.analyze(raw_banner, res['port'])
                
                version_str = fp['product']
                if fp['version'] != "Unknown":
                    version_str += f" {fp['version']}"
                    
                os_str = fp['os'] if fp['os'] != "Unknown" else ""
                
                # If no fingerprint product detected, show raw banner (truncated)
                if fp['product'] == "Unknown":
                    version_str = banner_display[:25] # readable chunk

                print(f"{port_str:<8} {colorize(res['status'], Colors.GREEN):<19} {res['service']:<15} {version_str:<25} {os_str:<15}")

if __name__ == "__main__":
    main()
