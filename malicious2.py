import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Step 1: Load the dataset
def load_data(file_path):
    try:
        df = pd.read_excel(file_path)
        print("Data loaded successfully.")
        return df
    except Exception as e:
        print(f"Error loading file: {e}")
        return None

# Step 2: Preprocess the data
def preprocess_data(df):
    # Handle missing values (if any)
    df.fillna(0, inplace=True)

    # Convert categorical data (e.g., access type) to numeric form
    df_encoded = pd.get_dummies(df.drop(columns=['User_ID', 'IP_Address', 'Admin_Flag', 'Unusual_Login']), drop_first=True)

    # Standardize the data for better anomaly detection
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(df_encoded)

    return scaled_data, df

# Step 3: Apply Isolation Forest for anomaly detection
def detect_anomalies(scaled_data):
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(scaled_data)
    predictions = model.predict(scaled_data)  # -1 for anomaly, 1 for normal
    return predictions

# Step 4: Main function to execute the detection process
def main(file_path):
    # Load the data
    df = load_data(file_path)
    if df is None:
        return

    # Preprocess the data
    scaled_data, original_df = preprocess_data(df)

    # Detect anomalies
    original_df['Malicious'] = detect_anomalies(scaled_data)

    # Identify the type of culprit
    original_df['Culprit_Type'] = original_df.apply(
        lambda row: "Admin Account Misuse" if row['Admin_Flag'] == 1 and row['Malicious'] == -1
        else "Misuse of Admin Privileges" if row['Admin_Flag'] == 0 and row['Malicious'] == -1
        else "Compromised Password" if row['Unusual_Login'] == 1 and row['Malicious'] == -1
        else "Normal Activity", axis=1
    )

    # Filter to show only malicious insiders
    malicious_insiders = original_df[original_df['Malicious'] == -1]

    # Display malicious insiders with User_ID, IP_Address, and Culprit_Type
    print("Detected Malicious Insiders:")
    print(malicious_insiders[['User_ID', 'IP_Address', 'Culprit_Type']])

    # Save results to an Excel file for further review
    malicious_insiders.to_excel('detected_malicious_insiders_with_culprit_type.xlsx', index=False)
    print("\nResults saved to 'detected_malicious_insiders_with_culprit_type.xlsx'.")

# Provide the path to your dataset file
file_path = 'organization_dataset_with_admin_and_login.xlsx'  # Replace this with your file's path
main(file_path)
