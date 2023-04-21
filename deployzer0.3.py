import os
import subprocess
import re
from tqdm import tqdm
import csv
import nmap
import traceback
import sys
import time

# Get the directory where the script is running and update the PATH environment variable
script_directory = os.path.dirname(os.path.abspath(sys.argv[0]))
os.environ["PATH"] = f"{script_directory};{os.environ['PATH']}"

try:
    def get_local_ipv4():
        # Get local IP address using ipconfig (Windows) or ifconfig (Unix-based systems)
        local_ip = subprocess.getoutput("ipconfig" if os.name == 'nt' else "ifconfig")
        # Extract IPv4 addresses from the output
        ipv4 = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", local_ip)
        # Return the first valid local IPv4 address (not 127.x.x.x or 169.254.x.x)
        return [ip for ip in ipv4 if not ip.startswith('127.') and not ip.startswith('169.254.')][0]

    def get_subnet(ipv4):
        # Determine the subnet based on the IPv4 address
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
        # Set the nmap arguments for scanning
        nmap_args = f'nmap -p 139,445 --open -O --osscan-guess -v -oG - {subnet}'
        print(f'Starting scan for {target_count} Windows machines...')
        start_time = time.time()
        # Run nmap with the specified arguments
        nmap_output = subprocess.run(nmap_args, shell=True, capture_output=True, text=True)

        # Initialize an empty list to store Windows machines
        windows_machines = []
        # Iterate through each line of nmap output
        for line in nmap_output.stdout.splitlines():
            if 'Windows' in line:
                # Find IP address of the Windows machine
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    # Append the IP address to the list and print the IP and hostname
                    windows_machines.append(match.group(1))
                    print(f'Found Windows machine: {match.group(1)}')
                    # Stop searching when the target number of Windows machines is found
                    if len(windows_machines) >= target_count:
                        break

        # Calculate the elapsed time for the scan by subtracting the start time from the current time
        elapsed_time = time.time() - start_time
        # Print the elapsed time, formatted to display 2 decimal places
        print(f'Elapsed time: {elapsed_time:.2f} seconds\n')

        # Return the list of Windows machines found during the scan
        return windows_machines

# Ask the user to input the path of the Python script they want to run on the remote Windows machines
print("Enter the path to the Python script you want to run on the remote Windows machines:")
script_path = input().strip()

# Check if the provided script path exists, if not, exit with an error message
if not os.path.exists(script_path):
    print(f"Script not found: {script_path}")
    exit(1)

# Get the local IPv4 address and subnet of the machine running the script
ipv4 = get_local_ipv4()
subnet = get_subnet(ipv4)

# Print a message indicating that the network scan is starting
print("Scanning the network for the first 3 Windows machines...")
# Call the function to scan the network for Windows machines and store the result in a list
windows_machines = scan_windows_machines(subnet)

# Count the total number of machines found, and initialize counters for successful and failed script executions
total_machines = len(windows_machines)
successful_executions = 0
failed_executions = 0
# Initialize an empty list to store the execution results
execution_results = []

print(f"Total machines found: {total_machines}")

# Iterate over the IP addresses of the Windows machines found
for ip in tqdm(windows_machines, desc="Executing script", unit="machine"):
    print(f"Deploying and running script on {ip}")

    # Retrieve the hostname of the remote Windows machine
    hostname = subprocess.getoutput(f"psexec \\\\{ip} -u .---s -p 123456 cmd /c hostname").strip()

    # Copy the script file to the remote Windows machine
    copy_command = f"psexec \\\\{ip} -u .---s -p 123456 -c -f {script_path}"
    copy_result = os.system(copy_command)

    # Check if the copy operation was successful
    if copy_result == 0:
        # Execute the script on the remote Windows machine
        run_command = f"psexec \\\\{ip} -u .---s -p 123456 -i -d python.exe {os.path.basename(script_path)}"
        run_result = os.system(run_command)

        # Check if the execution was successful
        if run_result == 0:
            successful_executions += 1
            execution_results.append([hostname, "Successful"])
        else:
            failed_executions += 1
            execution_results.append([hostname, "Failed"])

        # Delete the script file from the remote Windows machine
        delete_command = f"psexec \\\\{ip} -u .---s -p 123456 cmd /c del {os.path.basename(script_path)}"
        os.system(delete_command)
    else:
        failed_executions += 1
        execution_results.append([hostname, "Failed"])

    # Print summary of the script execution results
    print(f"Script execution completed on all detected Windows machines.")
    print(f"Total successful executions: {successful_executions}")
    print(f"Total failed executions: {failed_executions}")

    # Save the execution results to a CSV file
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
