import asyncio
import argparse
from colorama import init, Fore
from core.network import AsyncNetworkScanner
from core.secrets import SecretScanner

# Initialize colorama for colored terminal outputs
init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description="Portfolio SecScanner v1.0 (Async AppSec/Network Audit)")
    parser.add_argument("-t", "--target", help="Target domain or host IP for network scans")
    parser.add_argument("-p", "--ports", default="80,443,8080", help="Comma-separated target ports")
    parser.add_argument("-s", "--secret-file", help="Local configuration/env file path to scan for leaks")
    
    args = parser.parse_args()

    print(Fore.CYAN + "==================================================")
    print(Fore.CYAN + "     PORTFOLIO SECURITY AUDIT SCANNER STARTED     ")
    print(Fore.CYAN + "==================================================")

    # Execution path 1: Network Engine
    if args.target:
        port_list = [int(p.strip()) for p in args.ports.split(",")]
        print(Fore.YELLOW + f"[*] Launching async engine against: {args.target}")
        net_scanner = AsyncNetworkScanner(args.target, port_list)
        
        # Core async engine activation loop
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        if loop.is_running():
            # Handle execution if an event loop is already open (common in Pyroid environments)
            open_ports = asyncio.run_coroutine_threadsafe(net_scanner.run(), loop).result()
        else:
            open_ports = loop.run_until_complete(net_scanner.run())
        
        if open_ports:
            for item in open_ports:
                print(Fore.GREEN + f"[+] PORT {item['port']}: OPEN | Banner: {item['banner']}")
        else:
            print(Fore.RED + "[-] No active targets identified on selected port arrays.")

    # Execution path 2: Code Review Secret Engine
    if args.secret_file:
        print(Fore.YELLOW + f"\n[*] Launching static analysis signature array against: {args.secret_file}")
        sec_scanner = SecretScanner()
        leaks = sec_scanner.scan_file(args.secret_file)
        
        if leaks:
            for leak in leaks:
                print(Fore.RED + f"[CRITICAL LEAK] Line {leak['line']}: Detected {leak['type']} -> Context: {leak['snippet']}")
        else:
            print(Fore.GREEN + "[+] Static scan clean. No matching explicit secrets found.")

if __name__ == "__main__":
    main()
