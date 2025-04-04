import threading
import requests
import argparse
from dotenv import load_dotenv
import ipaddress

# Load environment variables from .env file
load_dotenv()

import time

def scan_ip(ip_address, output_file=None):
    retries = 3
    for attempt in range(retries):
        try:
            url = f"http://{ip_address}/phpinfo.php"
            response = requests.get(url, timeout=10)
            status_code = response.status_code

            # Save all responses with status codes if output file is specified
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"{ip_address} - Status: {status_code}\n")

            # Check if it's a successful response
            if status_code == 200 and "PHP Version" in response.text:
                print(f"[+] phpinfo.php found on: {ip_address} (Status: {status_code})")
                if output_file:
                    phpinfo_file = f"{output_file}_phpinfo"
                    with open(phpinfo_file, "a") as f:
                        f.write(f"{ip_address} - Status: {status_code}\n")
                return  # Exit retry loop on success
            else:
                print(f"[*] Response from {ip_address} with status code: {status_code}")
        except requests.exceptions.ConnectTimeout as e:
            with open("error_log.txt", "a") as f:
                f.write(f"Connection timeout scanning {ip_address}: {e}\n")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"{ip_address} - Status: Connection timeout\n")
            print(f"[-] Connection timeout scanning {ip_address}: {e}")
        except requests.exceptions.ReadTimeout as e:
            with open("error_log.txt", "a") as f:
                f.write(f"Read timeout scanning {ip_address}: {e}\n")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"{ip_address} - Status: Read timeout\n")
            print(f"[-] Read timeout scanning {ip_address}: {e}")
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            with open("error_log.txt", "a") as f:
                f.write(f"HTTP Error scanning {ip_address}: {e} (Status: {status_code})\n")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"{ip_address} - Status: {status_code}\n")
            print(f"[-] HTTP Error scanning {ip_address}: {e} (Status: {status_code})")
        except requests.exceptions.RequestException as e:
            with open("error_log.txt", "a") as f:
                f.write(f"Error scanning {ip_address}: {e}\n")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"{ip_address} - Status: Connection failed\n")
            print(f"[-] Error scanning {ip_address}: {e}")
        except Exception as e:
            with open("error_log.txt", "a") as f:
                f.write(f"Unexpected error scanning {ip_address}: {e}\n")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"{ip_address} - Status: Unknown error\n")
            print(f"[-] Unexpected error scanning {ip_address}: {e}")

        if attempt < retries - 1:
            time.sleep(2 ** attempt)  # Exponential backoff
    else:
        with open("error_log.txt", "a") as f:
            f.write(f"Failed to scan {ip_address} after {retries} attempts.\n")
        if output_file:
            with open(output_file, "a") as f:
                f.write(f"{ip_address} - Status: Failed after {retries} attempts\n")
        print(f"[-] Failed to scan {ip_address} after {retries} attempts.")

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
    parser.add_argument("-o", "--output", help="Output file to save scan results (if not specified, results will only be displayed in console)")
    args = parser.parse_args()

    output_file = args.output

    # Create or clear the output files only if output file is specified
    if output_file:
        # Create or clear the scan results file
        with open(output_file, "w") as f:
            f.write(f"--- Scan started at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")

        # Create or clear the phpinfo results file
        phpinfo_file = f"{output_file}_phpinfo"
        with open(phpinfo_file, "w") as f:
            f.write(f"--- Successful phpinfo.php findings at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        print(f"[*] Saving results to {output_file} and {phpinfo_file}")

    ip_range = get_ip_range(args.cidr)
    if ip_range:
        threads = []
        for ip in ip_range:
            thread = threading.Thread(target=scan_ip, args=(ip, output_file))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

if __name__ == "__main__":
    main()
