import requests
from requests.auth import HTTPBasicAuth
import urllib3
import configparser
import os
import csv
import datetime

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
    pat = config[instance_name]["pat"]
except KeyError:
    print(f"Credentials not found for {instance_name}. Please update the config file.")
    exit(1)

# Basic authentication setup
auth = HTTPBasicAuth(username, pat)


# Verify authentication
def verify_authentication():
    """
    Verifies that the authentication credentials are valid.
    """
    try:
        response = requests.get(f"{jira_url}/rest/api/3/myself", auth=auth, verify=False)
        if response.status_code == 200:
            print("Authentication successful.")
            return True
        elif response.status_code == 401:
            print("Authentication failed: Invalid credentials.")
        elif response.status_code == 403:
            print("Authentication failed: Access forbidden. Check user permissions.")
        else:
            print(f"Authentication failed: Unexpected status code {response.status_code}.")
            print(f"Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Jira instance: {e}")
    return False


# Delete user function
def delete_user(user_account_id):
    delete_url = f"{jira_url}/rest/api/3/user?accountId={user_account_id}"
    try:
        response = requests.delete(delete_url, auth=auth, verify=False)
        if response.status_code == 204:
            return True, "User successfully deleted"
        else:
            return False, f"Failed to delete user. Status code: {response.status_code}. Response: {response.text}"
    except requests.exceptions.RequestException as e:
        return False, f"Error connecting to Jira instance: {e}"


# Generate log file name
def generate_log_file_name():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"export-users-test_log_{timestamp}.csv"


# Process users from CSV
def process_users_from_csv(input_file):
    log_file = generate_log_file_name()

    if not os.path.exists(input_file):
        print(f"CSV file '{input_file}' not found. Exiting script.")
        return

    with open(input_file, "r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        last_access_columns = [col for col in reader.fieldnames if "Last seen" in col]

        if not {"User id", "User name", "email", "Added to org"}.issubset(reader.fieldnames):
            print("CSV file does not contain the required columns. Exiting.")
            return

        with open(log_file, "w", newline="", encoding="utf-8") as log:
            writer = csv.writer(log)
            writer.writerow(["User id", "Username", "Email", "Result"])

            for row in reader:
                user_id = row["User id"].strip()
                username = row.get("User name", "N/A").strip()
                email = row.get("email", "N/A").strip()
                added_to_org = row["Added to org"].strip()

                if added_to_org == "6-Feb-25" and all(
                        row[col].strip() == "Never accessed" for col in last_access_columns):
                    success, message = delete_user(user_id)
                    print(f"User ID: {user_id}, Username: {username}, Email: {email}, Result: {message}")
                    writer.writerow([user_id, username, email, message])

    print(f"Log file generated: {log_file}")


# Main script functionality
if __name__ == "__main__":
    if verify_authentication():
        input_file = input("Enter the path to the CSV file: ").strip()
        process_users_from_csv(input_file)
    else:
        print("Authentication verification failed. Exiting script.")
