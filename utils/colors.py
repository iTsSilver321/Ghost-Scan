import os
import sys

# Enable ANSI colors on Windows 10/11
if os.name == 'nt':
    os.system('color')

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

def colorize(text: str, color: str) -> str:
    """Wraps text in ANSI color code."""
    return f"{color}{text}{Colors.RESET}"

def print_banner(version: str):
    banner_art = f"""
{Colors.CYAN}   ______  __  ______  __________     ______________  _  __{Colors.RESET}
{Colors.CYAN}  / ____/ / / / / __ \/ ___/_  __/   / ___/ ____/   |/ |/ /{Colors.RESET}
{Colors.CYAN} / / __  / /_/ / / / /\__ \ / /_____ \__ \ /   / /| ||   / {Colors.RESET}
{Colors.CYAN}/ /_/ / / __  / /_/ /___/ // /_____/___/ / /___/ ___ |/   |  {Colors.RESET}
{Colors.CYAN}\____/ /_/ /_/\____//____//_/      /____/\____/_/  |_/_/|_|  {Colors.RESET}

               {Colors.BOLD}Ghost Scan v{version}{Colors.RESET}
"""
    print(banner_art)
