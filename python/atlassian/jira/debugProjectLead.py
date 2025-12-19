import csv
import requests
from requests.auth import HTTPBasicAuth

# Configuration
API_URL = "https://jira.app.vumc.org/rest/api/2/project/NO"
USERNAME = "morgac9"  # Replace with actual username
API_TOKEN = "12Bucklemy!"  # Replace with actual API token
OUTPUT_CSV = "output.csv"


def fetch_project_data(url, auth):
    """Fetch project data from the Jira API."""
    try:
        response = requests.get(url, auth=auth)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching project data: {e}")
        return None


def extract_project_details(project_data):
    """Extract project details including the lead's display name."""
    try:
        project_name = project_data.get("name", "Unknown")
        project_key = project_data.get("key", "Unknown")

        # Debugging: Print the entire "lead" object
        lead_data = project_data.get("lead", {})
        print(f"Lead Data (Raw): {lead_data}")

        # Extract display name from the lead field
        lead_display_name = lead_data.get("displayName", "Unknown")

        # Debugging: Log extracted display name
        print(f"Extracted Lead Display Name: {lead_display_name}")

        return project_name, project_key, lead_display_name
    except Exception as e:
        print(f"Error extracting project details: {e}")
        return "Unknown", "Unknown", "Unknown"


def write_to_csv(file_path, project_details):
    """Write project details to a CSV file."""
    try:
        with open(file_path, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Project Name", "Key", "Lead"])
            writer.writerow(project_details)
        print(f"CSV written successfully to {file_path}")
    except Exception as e:
        print(f"Error writing to CSV: {e}")


def main():
    """Main function to fetch project data and write to CSV."""
    print("Starting script...")
    auth = HTTPBasicAuth(USERNAME, API_TOKEN)
    project_data = fetch_project_data(API_URL, auth)

    if project_data:
        # Debugging: Print the raw JSON data
        print("Raw Project Data:")
        print(project_data)

        project_details = extract_project_details(project_data)

        # Debugging: Print extracted project details
        print("Extracted Project Details:")
        print(f"Name: {project_details[0]}, Key: {project_details[1]}, Lead: {project_details[2]}")

        write_to_csv(OUTPUT_CSV, project_details)
    else:
        print("Failed to fetch project data.")


if __name__ == "__main__":
    main()
