import csv
import os
import re


def extract_filter_blocks(content):
    """Extracts filter blocks from the given content."""
    return re.findall(r"\nFilter ID: (\d+)\n(.*?)\}\n-+\n", content, re.DOTALL)


def parse_filter_block(block):
    """Parses a single filter block and extracts required fields."""
    try:
        filter_id = re.search(r"'id': '([^']+)'", block)
        name = re.search(r"'name': '([^']+)'", block)
        owner = re.search(r"'displayName': '([^']+)'", block)
        jql = re.search(r"'jql': '([^']+)'", block)
        view_url = re.search(r"'viewUrl': '([^']+)'", block)
        share_permissions = re.search(r"'sharePermissions': (\[.*?\])", block)

        filter_id = filter_id.group(1) if filter_id else ''
        name = name.group(1) if name else ''
        owner = owner.group(1) if owner else ''
        jql = jql.group(1) if jql else ''
        view_url = view_url.group(1) if view_url else ''
        share_status = "Private" if share_permissions and share_permissions.group(1) == '[]' else "Shared"

        return [filter_id, name, owner, jql, view_url, share_status]
    except AttributeError:
        return None


def analyze_jira_text():
    input_filename = input("Enter the input text filename (in the same directory as this script): ")
    if not os.path.isfile(input_filename):
        print(f"Error: The file '{input_filename}' does not exist.")
        return

    output_filename = "jira_filters_analysis.csv"

    try:
        with open(input_filename, 'r', encoding='utf-8') as text_file:
            content = text_file.read()

        filter_blocks = extract_filter_blocks(content)

        if not filter_blocks:
            print("No valid filter blocks found in the file.")
            return

        with open(output_filename, 'w', newline='', encoding='utf-8') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(
                ["Filter ID", "Filter Name", "Owner Name", "Filter JQL", "Filter Link", "Shared/Private"])

            for filter_id, block in filter_blocks:
                parsed_data = parse_filter_block(block)
                if parsed_data:
                    csv_writer.writerow(parsed_data)
                else:
                    print(f"Error processing Filter ID {filter_id}: Malformed data.")

        print(f"Analysis completed. Output saved to '{output_filename}'")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    analyze_jira_text()
