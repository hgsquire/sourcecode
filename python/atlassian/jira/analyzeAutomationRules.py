import json
import csv

# File paths
INPUT_FILE = "jira_automation_export.json"  # JSON file with automation rules
OUTPUT_FILE = "jira_automation_rules.csv"  # Output CSV file
USERS_FILE = "HIT_prod_users.csv"          # CSV file mapping user IDs to display names
PROJECTS_FILE = "HIT_prod_projects.csv"    # CSV file mapping project IDs to project names

def load_csv_to_dict(file_path, key_column, value_column):
    """
    Load a CSV file into a dictionary.
    :param file_path: Path to the CSV file.
    :param key_column: Column to use as dictionary keys.
    :param value_column: Column to use as dictionary values.
    :return: Dictionary with keys and values from the specified columns.
    """
    data_dict = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                data_dict[row[key_column]] = row[value_column]
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return data_dict

def analyze_automation_rules(input_file, users_file, projects_file, output_file):
    try:
        # Load user and project mappings
        users_mapping = load_csv_to_dict(users_file, "Jira ID", "Display Name")
        projects_mapping = load_csv_to_dict(projects_file, "Project ID", "Project Name")

        # Read the JSON file
        with open(input_file, 'r', encoding='utf-8') as file:
            data = json.load(file)

        # Extract rules from the "rules" key
        rules = data.get("rules", [])
        if not rules:
            print("Error: No automation rules found in the JSON file.")
            return

        # Prepare data for CSV
        csv_data = []
        for rule in rules:
            name = rule.get("name", "N/A")
            owner_id = rule.get("authorAccountId", "N/A")
            owner_name = users_mapping.get(owner_id, "Unknown User")
            project_ids = [p.get("projectId", "N/A") for p in rule.get("projects", [])]
            project_names = [projects_mapping.get(pid, f"Unknown Project ({pid})") for pid in project_ids]
            projects_combined = ", ".join(project_names)
            enabled = rule.get("state", "").upper() == "ENABLED"

            csv_data.append({
                "Automation Name": name,
                "Owner": f"{owner_name} ({owner_id})",
                "Associated Projects": projects_combined,
                "Enabled": "Yes" if enabled else "No"
            })

        # Write to CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["Automation Name", "Owner", "Associated Projects", "Enabled"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            writer.writerows(csv_data)

        print(f"CSV file '{output_file}' has been created successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    analyze_automation_rules(INPUT_FILE, USERS_FILE, PROJECTS_FILE, OUTPUT_FILE)
