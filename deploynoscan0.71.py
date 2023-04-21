import os
import subprocess
import re
from tqdm import tqdm
import csv
import traceback
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
import keyring
import concurrent.futures


def get_local_ipv4():
    local_ip = subprocess.getoutput("ipconfig" if os.name == 'nt' else "ifconfig")
    ipv4 = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", local_ip)
    valid_ips = [ip for ip in ipv4 if not ip.startswith('127.') and not ip.startswith('169.254.')]
    if len(valid_ips) == 0:
        raise ValueError("No valid local IPv4 address found.")
    return valid_ips[0]


def get_subnet(ipv4):
    ip_parts = ipv4.split('.')
    if ip_parts[0] == '10':
        subnet = f"{ip_parts[0]}.0.0.0/8"
    elif ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.0.0/12"
    elif ip_parts[0] == '192' and ip_parts[1] == '168':
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    else:
        raise ValueError("Invalid IP address for private network.")
    return subnet


def scan_windows_machines(subnet):
    nmap_args = f'nmap -p 139,445 --open -O --osscan-guess -v -oG - {subnet}'
    try:
        nmap_proc = subprocess.Popen(nmap_args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as e:
        raise RuntimeError(f"Error running nmap command: {e}")

    windows_machines = []
    for line in iter(nmap_proc.stdout.readline, b''):
        print(line.decode().strip())
        if 'Windows' in line.decode():
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line.decode())
            if match:
                windows_machines.append(match.group(1))

    return windows_machines


def deploy_and_run_script(ip, file_path, username, password):
    copy_command = f"psexec \\\\{ip} -u {username} -p {password} -c -f {file_path}"
    copy_result = subprocess.call(copy_command, shell=True)

    if copy_result == 0:
        run_command = f"psexec \\\\{ip} -u {username} -p {password} -i -d {os.path.basename(file_path)}"
        run_result = subprocess.call(run_command, shell=True)
        delete_command = f"psexec \\\\{ip} -u {username} -p {password} cmd /c del {os.path.basename(file_path)}"
        subprocess.call(delete_command, shell=True)
        return run_result
    else:
        return 1


def main():
    check_nmap_availability()
    parser = argparse.ArgumentParser(description="Execute a script or program on remote Windows machines")
    parser.add_argument("-u", "--username", required=True, help="Username for the remote Windows machine")
    parser.add_argument("-s", "--service-name", required=True, help="Service name for the keyring password storage")
    parser.add_argument("file_path", help="Path to the script or program to run on the remote Windows machines")
    parser.add_argument("-t", "--targets", help="File containing the target IP addresses (skips network scan)")
    parser.add_argument('--version', action='version', version='%(prog)s 0.71')
    
    args = parser.parse_args()

    file_path = args.file_path

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        exit(1)

    ipv4 = get_local_ipv4()
    subnet = get_subnet(ipv4)

    if args.targets:
        with open(args.targets, 'r') as target_file:
            windows_machines = [line.strip() for line in target_file.readlines()]
            print(f"Using target IPs from file: {args.targets}")
    else:
        print("Scanning the network for Windows machines...")
        windows_machines = scan_windows_machines(subnet)

    total_machines = len(windows_machines)
    successful_executions = 0
    failed_executions = 0
    execution_results = []

    print(f"Total machines found: {total_machines}")

    username = args.username
    service_name = args.service_name
    password = keyring.get_password(service_name, username)

    if password is None:
        print(f"No password found in keyring for service '{service_name}' and username '{username}'")
        return

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(deploy_and_run_script, ip, file_path, username, password): ip for ip in windows_machines}
        for future in tqdm(concurrent.futures.as_completed(futures), total=total_machines, desc="Executing file", unit="machine"):
            ip = futures[future]
            try:
                run_result = future.result()
                hostname = subprocess.getoutput(f"psexec \\\\{ip} -u {username} -p {password} cmd /c hostname").strip()
                if run_result == 0:
                    successful_executions += 1
                    execution_results.append([hostname, "Successful"])
                else:
                    failed_executions += 1
                    execution_results.append([hostname, "Failed"])
            except Exception as e:
                failed_executions += 1
                execution_results.append([ip, "Failed"])

    print(f"Script execution completed on all detected Windows machines.")
    print(f"Total successful executions: {successful_executions}")
    print(f"Total failed executions: {failed_executions}")

    with open("execution_results.csv", mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Hostname", "Status"])
        writer.writerows(execution_results)

    print("Execution results saved to 'execution_results.csv'")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        error_message = traceback.format_exc()
        print(f"An error occurred: {e}")
        print("Detailed error message:")
        print(error_message)
        print("Press Enter to exit...")
        input()
