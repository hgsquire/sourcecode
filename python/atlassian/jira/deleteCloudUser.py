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
    "SDE_cloud": config["SDE_cloud"]["url"],
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

def delete_user(user_account_id):
    """
    Deletes a user from the Jira instance.
    :param user_account_id: The account ID of the user to be deleted.
    """
    delete_url = f"{jira_url}/rest/api/3/user?accountId={user_account_id}"
    try:
        response = requests.delete(delete_url, auth=auth, verify=False)
        if response.status_code == 204:
            print(f"User with account ID '{user_account_id}' has been successfully deleted.")
            return True, ""
        elif response.status_code == 403:
            error_message = "Permission denied. Ensure the user has proper permissions to delete accounts."
            print(error_message)
            return False, error_message
        else:
            error_message = f"Failed to delete user. Status code: {response.status_code}. Response: {response.text}"
            print(error_message)
            return False, error_message
    except requests.exceptions.RequestException as e:
        error_message = f"Error connecting to Jira instance: {e}"
        print(error_message)
        return False, error_message

def generate_log_file_name(base_name):
    """
    Generates a unique log file name based on the base name and current timestamp.
    :param base_name: The base name of the CSV file being processed.
    :return: A unique log file name.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file_name = f"{os.path.splitext(base_name)[0]}_log_{timestamp}.csv"
    return log_file_name

def process_users_from_csv(file_name):
    """
    Processes users from a CSV file and deletes them from Jira.
    :param file_name: Name of the CSV file containing user IDs.
    """
    log_file = generate_log_file_name(file_name)

    with open(file_name, "r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)

        if "User id" not in reader.fieldnames:
            print("CSV file does not contain 'User id' column. Exiting.")
            return

        with open(log_file, "w", newline="", encoding="utf-8") as log:
            writer = csv.writer(log)
            writer.writerow(["User id", "Status", "Error Message"])

            for row in reader:
                user_id = row["User id"].strip()
                if not user_id:
                    continue

                success, error_message = delete_user(user_id)
                if success:
                    writer.writerow([user_id, "Deleted", ""])
                else:
                    writer.writerow([user_id, "Failed", error_message])

    print(f"Log file generated: {log_file}")

# Main script functionality
if __name__ == "__main__":
    if verify_authentication():
        csv_file_name = input("Enter the name of the CSV file (located in the same directory as this script): ").strip()
        if os.path.exists(csv_file_name):
            process_users_from_csv(csv_file_name)
        else:
            print(f"CSV file '{csv_file_name}' not found. Exiting script.")
    else:
        print("Authentication verification failed. Exiting script.")
