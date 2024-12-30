import tkinter as tk
from tkinter import filedialog, messagebox
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
        messagebox.showerror("Error", f"Error loading file: {e}")
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


# Step 4: Process and analyze the dataset
def analyze_data(file_path):
    # Load the data
    df = load_data(file_path)
    if df is None:
        return None

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
    return malicious_insiders


# Step 5: GUI Implementation
class MaliciousInsiderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Malicious Insider Detection")
        self.file_path = ""

        # Widgets
        self.label = tk.Label(root, text="Malicious Insider Detection System", font=("Arial", 16))
        self.label.pack(pady=10)

        self.browse_button = tk.Button(root, text="Browse File", command=self.browse_file)
        self.browse_button.pack(pady=5)

        self.analyze_button = tk.Button(root, text="Run Analysis", command=self.run_analysis)
        self.analyze_button.pack(pady=5)

        self.result_text = tk.Text(root, height=15, width=80)
        self.result_text.pack(pady=10)

        self.save_button = tk.Button(root, text="Save Results", command=self.save_results)
        self.save_button.pack(pady=5)

        self.results = None  # To store malicious insider results

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(
            filetypes=[("Excel Files", "*.xlsx"), ("All Files", "*.*")]
        )
        if self.file_path:
            messagebox.showinfo("File Selected", f"File loaded: {self.file_path}")

    def run_analysis(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please select a file first.")
            return

        self.results = analyze_data(self.file_path)
        if self.results is None or self.results.empty:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "No malicious insiders detected.")
        else:
            # Display results in the text box
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(
                tk.END, self.results[['User_ID', 'IP_Address', 'Culprit_Type']].to_string(index=False)
            )
            messagebox.showinfo("Analysis Complete", "Malicious insiders detected!")

    def save_results(self):
        if self.results is None or self.results.empty:
            messagebox.showwarning("No Results", "No results to save.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Files", "*.xlsx"), ("All Files", "*.*")]
        )
        if save_path:
            self.results.to_excel(save_path, index=False)
            messagebox.showinfo("Saved", f"Results saved to {save_path}")


# Main Application
if __name__ == "__main__":
    root = tk.Tk()
    app = MaliciousInsiderApp(root)
    root.mainloop()
