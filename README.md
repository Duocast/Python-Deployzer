# Python-Deployzer

python deploy_xx.py -u username -p password script_to_run.py

python deploy_xx.py -u username -p password file_to_run.exe

python -m keyring set <service-name> <username>
Replace <service-name> and <username> with your desired values, and you'll be prompted to enter the password.

When running your script, pass the --service-name and --username arguments, and the script will retrieve the password securely from the keyring storage:
python deploy_xx.py -u <username> -s <service-name> <file_path>
