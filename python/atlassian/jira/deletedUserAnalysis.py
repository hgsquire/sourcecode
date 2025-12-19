import csv
import os


def filter_deleted_users(ref_file, log_file, output_file):
    # Read reference file into a dictionary
    ref_users = {}
    with open(ref_file, mode='r', encoding='utf-8') as ref:
        ref_reader = csv.DictReader(ref)
        for row in ref_reader:
            ref_users[row['User id']] = {
                'User id': row['User id'],
                'User name': row.get('User name', ''),
                'email': row.get('email', '')
            }

    # Process log file and filter users marked as Deleted
    deleted_users = []
    with open(log_file, mode='r', encoding='utf-8') as log:
        log_reader = csv.DictReader(log)
        for row in log_reader:
            user_id = row['User id']
            if row.get('status') == 'Deleted' and user_id in ref_users:
                deleted_users.append(ref_users[user_id])

    # Write output file
    if deleted_users:
        with open(output_file, mode='w', newline='', encoding='utf-8') as out:
            fieldnames = ['User id', 'User name', 'email']
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(deleted_users)
        print(f"Output file '{output_file}' created successfully with {len(deleted_users)} entries.")
    else:
        print("No matching deleted users found.")


if __name__ == "__main__":
    ref_filename = "export-users-refFile.csv"
    log_filename = "deleteUsersOnly_log_20250219_142457.csv"
    output_filename = "deleted_users_output.csv"

    if os.path.exists(ref_filename) and os.path.exists(log_filename):
        filter_deleted_users(ref_filename, log_filename, output_filename)
    else:
        print("One or both input files are missing in the current directory.")
