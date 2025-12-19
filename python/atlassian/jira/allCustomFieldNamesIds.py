import requests
from requests.auth import HTTPBasicAuth
import urllib3
import configparser
import os
import csv

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration file for URLs and credentials
config_file = "jira_config.ini"

# Check if the configuration file exists
if not os.path.exists(config_file):
    print(f"Configuration file '{config_file}' not found. Please create one.")
    exit(1)

# Read configuration
config = configparser.ConfigParser()
config.read(config_file)

# Define Jira instances
instances = {
    "HIT_prod": config["HIT_prod"]["url"],
    "HIT_test": config["HIT_test"]["url"],
    "ADI_prod": config["ADI_prod"]["url"],
    "ADI_test": config["ADI_test"]["url"],
    "VEC_prod": config["VEC_prod"]["url"],
    "VEC_test": config["VEC_test"]["url"],
    "HIT_Cloud_prod": config["HIT_Cloud_prod"]["url"],
    "ADI_Cloud_prod": config["ADI_Cloud_prod"]["url"],
    "HIT_sandbox": config["HIT_sandbox"]["url"],
    "ADI_sandbox": config["ADI_sandbox"]["url"],
    "VEC_sandbox": config["VEC_sandbox"]["url"],
}

# Prompt user to select an instance
print("Available Jira instances:")
for i, instance in enumerate(instances.keys(), 1):
    print(f"{i}. {instance}")
choice = input("Select an instance by number: ").strip()

try:
    instance_name = list(instances.keys())[int(choice) - 1]
    jira_url = instances[instance_name]
except (IndexError, ValueError):
    print("Invalid choice. Exiting script.")
    exit(1)

# Load credentials for the chosen instance
try:
    username = config[instance_name]["username"]
    pat = config[instance_name].get("pat", None)
    password = config[instance_name].get("password", None)
except KeyError:
    print(f"Credentials not found for {instance_name}. Please update the config file.")
    exit(1)

# Set up authentication
auth = None

# Attempt PAT authentication first
if pat:
    print("Attempting authentication using PAT...")
    auth = HTTPBasicAuth(username, pat)
    test_url = f"{jira_url}/rest/api/2/field"
    test_response = requests.get(test_url, auth=auth, verify=False)
    if test_response.status_code == 200:
        print("Authenticated successfully using PAT.")
    else:
        print("Authentication failed using PAT.")
        auth = None

# If PAT authentication fails, attempt basic authentication
if not auth and password:
    print("Attempting authentication using username and password...")
    auth = HTTPBasicAuth(username, password)
    test_response = requests.get(test_url, auth=auth, verify=False)
    if test_response.status_code == 200:
        print("Authenticated successfully using username and password.")
    else:
        print("Authentication failed using username and password.")
        exit(1)

def fetch_custom_fields():
    """Fetches all custom fields from Jira and saves them to a CSV file."""
    custom_fields_url = f"{jira_url}/rest/api/2/field"
    response = requests.get(custom_fields_url, auth=auth, verify=False)

    if response.status_code != 200:
        print(f"Failed to fetch custom fields. Status Code: {response.status_code}")
        return

    custom_fields = response.json()
    output_file = f"custom_fields_{instance_name}.csv"

    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Custom Field Name", "Custom Field ID"])

        for field in custom_fields:
            if field.get("custom"):
                writer.writerow([field["name"].strip(), field["id"].strip()])

    print(f"Custom fields written to {output_file}.")

def compare_custom_fields(custom_fields_csv, compare_file):
    """Compares two files and outputs a mapping of custom field names to IDs."""
    field_map = {}

    # Load Jira custom field data
    with open(custom_fields_csv, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            field_map[row["Custom Field Name"].strip()] = row["Custom Field ID"].strip()

    # Process the second file and match names to IDs
    output_file = "custom_field_mapping.csv"
    with open(compare_file, mode="r", encoding="utf-8") as file, \
         open(output_file, mode="w", newline="", encoding="utf-8") as output:

        writer = csv.writer(output)
        writer.writerow(["Custom Field Name", "Custom Field ID"])

        for line in file:
            field_name = line.strip()
            if field_name:  # Skip empty lines
                field_id = field_map.get(field_name, "Not Found")
                writer.writerow([field_name, field_id])

    print(f"Custom field mapping written to {output_file}.")

def main():
    """Main function to execute the script."""
    print("\nSelect an option:")
    print("1. Fetch all custom fields and save to CSV.")
    print("2. Compare custom field files and create a mapping.")
    print("3. Exit.")

    choice = input("Enter your choice (1/2/3): ").strip()

    if choice == "1":
        fetch_custom_fields()
    elif choice == "2":
        custom_fields_csv = input("Enter the path to the Jira custom fields CSV: ").strip()
        compare_file = input("Enter the path to the file with custom field names: ").strip()
        
        if not os.path.exists(custom_fields_csv):
            print(f"Error: File '{custom_fields_csv}' not found.")
            return
        if not os.path.exists(compare_file):
            print(f"Error: File '{compare_file}' not found.")
            return

        compare_custom_fields(custom_fields_csv, compare_file)
    elif choice == "3":
        print("Exiting script.")
        exit(0)
    else:
        print("Invalid choice. Exiting script.")

if __name__ == "__main__":
    main()
