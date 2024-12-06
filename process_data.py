import pandas as pd

# Read the JSON data from phishing URLs file
phishing_df = pd.read_json('phisihing_urls_features.json')
# Add a "label" column with the value 0
phishing_df['label'] = 0

# Read the JSON data from safe URLs file
safe_df = pd.read_json('safe_urls_features.json')
# Add a "label" column with the value 1
safe_df['label'] = 1

# Merge the two DataFrames on common columns
merged_df = pd.concat([phishing_df, safe_df], ignore_index=True)

# Drop columns with null values
cleaned_df = merged_df.dropna(axis=1)

# Store the cleaned DataFrame into a CSV file
cleaned_df.to_csv('cleaned_merged_urls_features.csv', index=False)

print("Data has been successfully saved to cleaned_merged_urls_features.csv")