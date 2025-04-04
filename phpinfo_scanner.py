import socket
import threading
import requests
import argparse
import os
from dotenv import load_dotenv
import ipaddress

# Load environment variables from .env file
load_dotenv()

def scan_ip(ip_address):
    try:
        url = f"http://{ip_address}/phpinfo.php"
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        if "PHP Version" in response.text:
            print(f"[+] phpinfo.php found on: {ip_address}")
            with open("phpinfo_results.txt", "a") as f:
                f.write(f"{ip_address}\n")
    except requests.exceptions.RequestException as e:
        with open("error_log.txt", "a") as f:
            f.write(f"Error scanning {ip_address}: {e}\n")
        print(f"[-] Error scanning {ip_address}: {e}")
    except Exception as e:
        with open("error_log.txt", "a") as f:
            f.write(f"Unexpected error scanning {ip_address}: {e}\n")
        print(f"[-] Unexpected error scanning {ip_address}: {e}")

def get_ip_range(cidr):
    try:
        network = ipaddress.ip_network(cidr)
        return [str(ip) for ip in network]
    except ValueError:
        print(f"[-] Invalid CIDR notation: {cidr}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Scan for phpinfo.php in an IP range.")
    parser.add_argument("cidr", help="IP range in CIDR notation (e.g., 192.168.1.0/24)")
    args = parser.parse_args()

    ip_range = get_ip_range(args.cidr)
    if ip_range:
        threads = []
        for ip in ip_range:
            thread = threading.Thread(target=scan_ip, args=(ip,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

if __name__ == "__main__":
    main()
