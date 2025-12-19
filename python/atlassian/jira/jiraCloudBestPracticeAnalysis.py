import requests
import configparser
import os
import urllib3
from datetime import datetime
from requests.auth import HTTPBasicAuth
import json
from tqdm import tqdm
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
from fpdf import FPDF
from tabulate import tabulate
import csv
import pandas as pd

# --- Disable SSL warnings ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Config ---
config_file = "jira_config.ini"
config = configparser.ConfigParser()
config.read(config_file)

# Load only valid Jira instances with required keys
instances = {
    section: config[section]["url"]
    for section in config.sections()
    if all(k in config[section] for k in ("url", "username", "pat"))
}

if not instances:
    print("No valid Jira instances found in the config file.")
    exit(1)

print("\nAvailable Jira instances:")
for i, k in enumerate(instances.keys(), 1):
    print(f"{i}. {k}")
choice = input("Select an instance: ").strip()
instance_name = list(instances.keys())[int(choice) - 1]

jira_url = config[instance_name]["url"].rstrip('/')
username = config[instance_name]["username"]
pat = config[instance_name]["pat"]
auth = HTTPBasicAuth(username, pat)

headers = {
    "Accept": "application/json"
}

output_dir = "jira_exports"
os.makedirs(output_dir, exist_ok=True)

def export_data(endpoint, filename):
    url = f"{jira_url}/rest/api/3/{endpoint}"
    response = requests.get(url, headers=headers, auth=auth, verify=False)
    if response.status_code == 200:
        with open(os.path.join(output_dir, filename), 'w', encoding='utf-8') as f:
            json.dump(response.json(), f, indent=4)
        print(f"Exported {filename}")
    else:
        print(f"Failed to fetch {filename}: {response.status_code} - {response.text}")

# --- Export operations ---
export_data("permissionscheme", "permission_schemes.json")
export_data("issuetypescheme", "issue_type_schemes.json")
export_data("workflowscheme", "workflow_schemes.json")
export_data("field", "custom_fields.json")
export_data("users/search?maxResults=1000", "users.json")
export_data("role", "project_roles.json")

# --- Analysis ---
def analyze_exports():
    analysis_report = []
    charts = []

    def load_json(filename):
        with open(os.path.join(output_dir, filename), 'r', encoding='utf-8') as f:
            return json.load(f)

    summary = {}

    # --- Custom Field Analysis ---
    fields = load_json("custom_fields.json")
    field_names = Counter(field.get("name") for field in fields)
    duplicate_fields = [name for name, count in field_names.items() if count > 1]
    summary['Total Custom Fields'] = len(fields)
    summary['Duplicate Custom Fields'] = len(duplicate_fields)

    if duplicate_fields:
        analysis_report.append("Duplicate Custom Fields Detected:")
        for name in duplicate_fields:
            analysis_report.append(f"  - {name} ({field_names[name]} times)")
    else:
        analysis_report.append("No duplicate custom fields found.")

    # Generate bar chart for custom field occurrences
    top_fields = field_names.most_common(10)
    plt.figure()
    plt.barh([name for name, _ in top_fields], [count for _, count in top_fields])
    plt.title("Top 10 Custom Fields by Occurrence")
    chart_path = os.path.join(output_dir, "custom_fields_chart.png")
    plt.tight_layout()
    plt.savefig(chart_path)
    charts.append(chart_path)

    # --- Permission Scheme Deep Analysis ---
    permission_data = load_json("permission_schemes.json")
    users_data = load_json("users.json")
    roles_data = load_json("project_roles.json")
    user_lookup = {u['accountId']: u for u in users_data if 'accountId' in u}
    role_lookup = {str(role["id"]): role["name"] for role in roles_data}

    ad_group_recommendations = []
    role_mappings = defaultdict(list)
    group_counts = Counter()
    user_permissions = []
    inactive_user_permissions = []

    permission_entries = []

    for scheme in permission_data.get("permissionSchemes", []):
        scheme_name = scheme.get("name")
        permissions = scheme.get("permissions", [])
        for p in permissions:
            perm_type = p.get("permission")
            holder = p.get("holder", {})
            h_type = holder.get("type")
            h_param = holder.get("parameter")

            display_val = h_param
            if h_type == "projectRole" and h_param in role_lookup:
                display_val = f"{role_lookup[h_param]} (ID: {h_param})"

            permission_entries.append([scheme_name, perm_type, h_type, display_val])

            if h_type == "projectRole":
                role_mappings[display_val].append((scheme_name, perm_type))
            elif h_type == "group":
                group_counts[h_param] += 1
            elif h_type == "user":
                user_permissions.append((scheme_name, perm_type, h_param))
                user_info = user_lookup.get(h_param)
                if user_info and not user_info.get("active", True):
                    inactive_user_permissions.append((scheme_name, perm_type, user_info.get("displayName", h_param)))

    # Save to CSV and Excel
    csv_file_path = os.path.join(output_dir, "permission_schemes_analysis.csv")
    df = pd.DataFrame(permission_entries, columns=["Scheme", "Permission", "Holder Type", "Value"])
    df.to_csv(csv_file_path, index=False)
    df.to_excel(csv_file_path.replace(".csv", ".xlsx"), index=False)

    summary['Total Permission Schemes'] = len(permission_data.get("permissionSchemes", []))
    summary['Roles in Permissions'] = len(role_mappings)
    summary['Groups in Permissions'] = len(group_counts)
    summary['Users Assigned Directly'] = len(user_permissions)
    summary['Inactive Users with Permissions'] = len(inactive_user_permissions)

    analysis_report.append("\nPermission Scheme Overview:")
    table_str = tabulate(permission_entries, headers=["Scheme", "Permission", "Holder Type", "Value"], tablefmt="grid")
    analysis_report.append(table_str)

    if user_permissions:
        analysis_report.append("\nUsers Directly Assigned Permissions:")
        for scheme, perm, user in user_permissions:
            user_name = user_lookup.get(user, {}).get("displayName", user)
            analysis_report.append(f"  - User '{user_name}' in scheme '{scheme}' for permission '{perm}'")

    if inactive_user_permissions:
        analysis_report.append("\nInactive Users Found in Permission Assignments:")
        for scheme, perm, user in inactive_user_permissions:
            analysis_report.append(f"  - Inactive user '{user}' in scheme '{scheme}' for permission '{perm}'")

    if group_counts:
        analysis_report.append("\nGroups in Use Across Permission Schemes:")
        for group, count in group_counts.most_common():
            analysis_report.append(f"  - {group}: used {count} times")

    for role, mappings in role_mappings.items():
        analysis_report.append(f"\nRole '{role}' is used in:")
        for scheme_name, perm in mappings:
            analysis_report.append(f"  - Scheme: {scheme_name}, Permission: {perm}")
        analysis_report.append(f"  > Recommend mapping to an AD group if not already.")

    # Pie chart of role vs group vs user usage
    plt.figure()
    plt.pie([len(role_mappings), len(group_counts), len(user_permissions)], labels=['Roles', 'Groups', 'Users'], autopct='%1.1f%%')
    plt.title("Permission Assignment Type Breakdown")
    perm_chart = os.path.join(output_dir, "permission_roles_groups_users.png")
    plt.tight_layout()
    plt.savefig(perm_chart)
    charts.append(perm_chart)

    # Write Reports
    with open(os.path.join(output_dir, "jira_analysis_report.txt"), 'w', encoding='utf-8') as f:
        f.write("Summary Dashboard:\n")
        for k, v in summary.items():
            f.write(f"- {k}: {v}\n")
        f.write("\n" + "\n".join(analysis_report))

    html_path = os.path.join(output_dir, "jira_analysis_report.html")
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write("<html><head><title>Jira Analysis Report</title></head><body>")
        f.write("<h1>Jira Analysis Report</h1><h2>Summary Dashboard</h2><ul>")
        for k, v in summary.items():
            f.write(f"<li><b>{k}</b>: {v}</li>")
        f.write("</ul><pre>" + "\n".join(analysis_report) + "</pre>")
        for chart in charts:
            f.write(f"<img src='{os.path.basename(chart)}' alt='Chart' style='max-width:800px;'><br>")
        f.write("</body></html>")

    pdf_path = os.path.join(output_dir, "jira_analysis_report.pdf")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, "Jira Analysis Report - Summary Dashboard\n")
    for k, v in summary.items():
        pdf.cell(0, 10, f"- {k}: {v}", ln=True)
    pdf.ln(5)
    pdf.multi_cell(0, 10, "\n".join(analysis_report))
    for chart in charts:
        pdf.add_page()
        pdf.image(chart, x=10, y=20, w=180)
    pdf.output(pdf_path)

    print("Analysis complete. See text, HTML, PDF, CSV, and Excel reports in the 'jira_exports' directory.")

analyze_exports()
