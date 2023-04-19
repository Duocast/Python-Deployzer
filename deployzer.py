import os
import subprocess
import re
from tqdm import tqdm
import csv
import nmap
import traceback
import os
import sys

script_directory = os.path.dirname(os.path.abspath(sys.argv[0]))
os.environ["PATH"] = f"{script_directory};{os.environ['PATH']}"

try:
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

    def scan_windows_machines(subnet):
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments='-p 139,445 --open -O --osscan-guess')
        windows_machines = [host for host in nm.all_hosts() if 'osclass' in nm[host] and 'osfamily' in nm[host]['osclass']['osclass'] and nm[host]['osclass']['osclass']['osfamily'] == 'Windows']
        return windows_machines

    ipv4 = get_local_ipv4()
    subnet = get_subnet(ipv4)

    windows_machines = scan_windows_machines(subnet)

    total_machines = len(windows_machines)
    successful_executions = 0
    failed_executions = 0
    execution_results = []

    print("Enter the path to the Python script you want to run on the remote Windows machines:")
    script_path = input().strip()

    if not os.path.exists(script_path):
        print(f"Script not found: {script_path}")
        exit(1)

    print(f"Total machines found: {total_machines}")

    for ip in tqdm(windows_machines, desc="Executing script", unit="machine"):
        print(f"Deploying and running script on {ip}")

        hostname = subprocess.getoutput(f"psexec \\\\{ip} -u [USERNAME] -p [PASSWORD] cmd /c hostname").strip()

        copy_command = f"psexec \\\\{ip} -u [USERNAME] -p [PASSWORD] -c -f {script_path}"
        copy_result = os.system(copy_command)

        if copy_result == 0:
            run_command = f"psexec \\\\{ip} -u [USERNAME] -p [PASSWORD] -i -d python.exe {os.path.basename(script_path)}"
            run_result = os.system(run_command)

            if run_result == 0:
                successful_executions += 1
                execution_results.append([hostname, "Successful"])
            else:
                failed_executions += 1
                execution_results.append([hostname, "Failed"])

            delete_command = f"psexec \\\\{ip} -u [USERNAME] -p [PASSWORD] cmd /c del {os.path.basename(script_path)}"
            os.system(delete_command)
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

except Exception as e:
    error_message = traceback.format_exc()
    print(f"An error occurred: {e}")
    print("Detailed error message:")
    print(error_message)
    print("Press Enter to exit...")
    input()
