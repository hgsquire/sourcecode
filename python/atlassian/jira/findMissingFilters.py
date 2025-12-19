import pandas as pd

# Define file names
file_analysis = "jira_filters_analysis.csv"
file_sandbox = "jira_filters_HIT_sandbox_20250304_132815.csv"
output_file = "jira_filters_not_in_sandbox_2.csv"

# Read CSV files
analysis_df = pd.read_csv(file_analysis)
sandbox_df = pd.read_csv(file_sandbox)

# Ensure "Filter Name" column exists in both files
if "Filter Name" not in analysis_df.columns or "Filter Name" not in sandbox_df.columns:
    raise ValueError("Missing 'Filter Name' column in one or both files.")

# Extract set of filter names from sandbox file
sandbox_filter_names = set(sandbox_df["Filter Name"].astype(str))

# Filter rows from analysis_df where "Filter Name" is not in sandbox_df
filtered_df = analysis_df[~analysis_df["Filter Name"].astype(str).isin(sandbox_filter_names)]

# Ensure the output file contains the "Filter Name" column
filtered_df = filtered_df[["Filter Name"] + [col for col in filtered_df.columns if col != "Filter Name"]]

# Save the output
filtered_df.to_csv(output_file, index=False)

print(f"Output saved to {output_file} with {len(filtered_df)} rows not found in the sandbox file.")
