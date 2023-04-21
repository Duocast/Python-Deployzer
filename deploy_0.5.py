import os
import subprocess
import re
from tqdm import tqdm
import csv
import traceback
import sys
import time
import argparse


def get_local_ipv4():
    local_ip = subprocess.getoutput("ipconfig" if os.name == 'nt' else "ifconfig")
    ipv4 = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", local_ip)
    return [ip for ip in ipv4 if not ip.startswith('127.') and not ip.startswith('169.254.')][0]


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


def scan_windows_machines(subnet, target_count=3):
    nmap_args = f'nmap -p 139,445 --open -O --osscan-guess -v -oG - {subnet}'
    start_time = time.time()
    nmap_output = subprocess.run(nmap_args, shell=True, capture_output=True, text=True)

    windows_machines = []
    for line in nmap_output.stdout.splitlines():
        if 'Windows' in line:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                windows_machines.append(match.group(1))
                if len(windows_machines) >= target_count:
                    break

    elapsed_time = time.time() - start_time
    return windows_machines


def deploy_script(ip, script_path, username, password):
    copy_command = f"psexec \\\\{ip} -u {username} -p {password} -c -f {script_path}"
    copy_result = os.system(copy_command)
    return copy_result


def execute_script(ip, script_path, username, password):
    run_command = f"psexec \\\\{ip} -u {username} -p {password} -i -d python.exe {os.path.basename(script_path)}"
    run_result = os.system(run_command)
    return run_result


def remove_script(ip, script_path, username, password):
    delete_command = f"psexec \\\\{ip} -u {username} -p {password} cmd /c del {os.path.basename(script_path)}"
    delete_result = os.system(delete_command)
    return delete_result


def main():
    parser = argparse.ArgumentParser(description="Execute a Python script on remote Windows machines")
    parser.add_argument("-u", "--username", required=True, help="Username for the remote Windows machine")
    parser.add_argument("-p", "--password", required=True, help="Password for the remote Windows machine")
    parser.add_argument("script_path", help="Path to the Python script to run on the remote Windows machines")

    args = parser.parse_args()

    script_path = args.script_path

    if not os.path.exists(script_path):
        print(f"Script not found: {script_path}")
        exit(1)

    ipv4 = get_local_ipv4()
    subnet = get_subnet(ipv4)

    print("Scanning the network for the first 3 Windows machines...")
    windows_machines = scan_windows_machines(subnet)

    total_machines = len(windows_machines)
    successful_executions = 0
    failed_executions = 0
    execution_results = []

    print(f"Total machines found: {total_machines}")

    username = args.username
    password = args.password

    for ip in tqdm(windows_machines, desc="Executing script", unit="machine"):
        print(f"Deploying and running script on {ip}")

        hostname = subprocess.getoutput(f"psexec \\\\{ip} -u {username} -p {password} cmd /c hostname").strip()

        copy_result = deploy_script(ip, script_path, username, password)

        if copy_result == 0:
            run_result = execute_script(ip, script_path, username, password)

            if run_result == 0:
                successful_executions += 1
                execution_results.append([hostname, "Successful"])
            else:
                failed_executions += 1
                execution_results.append([hostname, "Failed"])

            remove_result = remove_script(ip, script_path, username, password)
        else:
            failed_executions += 1
            execution_results.append([hostname, "Failed"])

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
