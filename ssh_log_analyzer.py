import re
from collections import Counter
import argparse # To accept filename as argument

def analyze_ssh_log(log_file_path, failure_threshold=5):
    """
    Analyzes an SSH auth.log file to detect potential brute-force attacks.

    Args:
        log_file_path (str): The path to the auth.log file.
        failure_threshold (int): The minimum number of failed logins
                                 from a single IP to trigger an alert.

    Returns:
        dict: A dictionary containing potentially malicious IPs and their
              failed login counts. Returns None if the file cannot be read.
    """
    # Regex to find failed password attempts and capture the IP address
    # Adjust regex if your log format differs slightly
    # Example line: "Failed password for invalid user test from 1.2.3.4 port 12345 ssh2"
    # Example line: "Failed password for root from 1.2.3.4 port 12345 ssh2"
    failed_login_pattern = re.compile(r"Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    ip_failure_counts = Counter() # Efficiently counts items

    print(f"[*] Analyzing log file: {log_file_path}")
    print(f"[*] Failure threshold set to: {failure_threshold}")

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                match = failed_login_pattern.search(line)
                if match:
                    ip_address = match.group(1)
                    ip_failure_counts[ip_address] += 1
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_file_path}")
        return None
    except Exception as e:
        print(f"[ERROR] An error occurred while reading the file: {e}")
        return None

    # Identify IPs exceeding the threshold
    potential_attackers = {}
    for ip, count in ip_failure_counts.items():
        if count >= failure_threshold:
            potential_attackers[ip] = count

    print("[*] Analysis Complete.")
    return potential_attackers

def print_report(attackers):
    """Prints a simple report of potential attackers."""
    print("\n--- SSH Brute-Force Analysis Report ---")
    if not attackers:
        print("[+] No IPs exceeded the failure threshold.")
    else:
        print(f"[!] Potential brute-force detected from {len(attackers)} IP(s):")
        # Sort by count descending for clarity
        sorted_attackers = sorted(attackers.items(), key=lambda item: item[1], reverse=True)
        for ip, count in sorted_attackers:
            print(f"  - IP Address: {ip:<15} | Failed Attempts: {count}")
    print("---------------------------------------\n")

# --- Main execution block ---
if __name__ == "__main__":
    # Setup command-line argument parsing
    parser = argparse.ArgumentParser(description="Analyze SSH auth.log for potential brute-force attacks.")
    parser.add_argument("logfile", help="Path to the auth.log file")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                        help="Failure threshold count (default: 5)")

    args = parser.parse_args()

    # Run the analysis
    suspicious_ips = analyze_ssh_log(args.logfile, args.threshold)

    # Print the report if analysis was successful
    if suspicious_ips is not None:
        print_report(suspicious_ips)