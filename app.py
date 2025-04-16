from flask import Flask, render_template, request
import pandas as pd
from encryption import encrypt_data, decrypt_data

app = Flask(__name__)

# Global dictionary to hold encrypted datasets for each category
datasets = {}

def load_and_encrypt_dataset(file_path):
    df = pd.read_excel(file_path)
    headings = list(df.columns)
    # Encrypt each cell as a string
    encrypted_data = df.applymap(lambda x: encrypt_data(str(x))).values.tolist()
    return headings, encrypted_data

# Pre-load datasets for each category
datasets["vitals"] = {}
datasets["vitals"]["headings"], datasets["vitals"]["data"] = load_and_encrypt_dataset('dataset/vitals.xlsx')

datasets["careplan"] = {}
datasets["careplan"]["headings"], datasets["careplan"]["data"] = load_and_encrypt_dataset('dataset/careplan.xlsx')

datasets["medication"] = {}
datasets["medication"]["headings"], datasets["medication"]["data"] = load_and_encrypt_dataset('dataset/medication.xlsx')

datasets["devices"] = {}
datasets["devices"]["headings"], datasets["devices"]["data"] = load_and_encrypt_dataset('dataset/devices.xlsx')

@app.route('/')
def dashboard():
    """Main dashboard with 4 emoji buttons."""
    return render_template('dashboard.html')

@app.route('/dataset/<category>', methods=['GET', 'POST'])
def view_dataset(category):
    """View and optionally decrypt the selected dataset."""
    if category not in datasets:
        return "Dataset not found", 404

    headings = datasets[category]["headings"]
    encrypted_data = datasets[category]["data"]
    decrypted = False

    if request.method == 'POST':
        key = request.form['decryption_key']
        # Attempt to decrypt each cell using the provided key
        decrypted_data = [[decrypt_data(cell, key) for cell in row] for row in encrypted_data]
        # Check if decryption is successful (assuming the first cell should not be "Invalid Key")
        if "Invalid Key" not in decrypted_data[0]:
            encrypted_data = decrypted_data
            decrypted = True

    return render_template('index.html',
                           category=category.title(),
                           headings=headings,
                           encrypted_data=encrypted_data,
                           decrypted=decrypted)

if __name__ == '__main__':
    app.run(debug=True)
