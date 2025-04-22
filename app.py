from flask import Flask, render_template, request, redirect, url_for, session, flash
import pickle
import numpy as np
import datetime
import pandas as pd
import random
from cryptography.fernet import Fernet
from encryption import init_encryption, encrypt_data, decrypt_data
import os  # 👈 ADDED

import smtplib
from email.mime.text import MIMEText

def send_block_alert_email(username):
    sender_email = "aateefahmamoon@gmail.com"
    receiver_email = "aateefahmamoon@gmail.com"
    app_password = "mvvd gyvj bnsw uomx"  

    subject = f"🚨 [Smart Hospital] Security Alert: User '{username}' Blocked Due to Suspicious Activity"

    body = f"""
Dear Admin,

We wanted to alert you that the user account **'{username}'** has been automatically blocked by the Smart Hospital Intrusion Detection System due to multiple suspicious login attempts.

📌 **Reason**: Multiple failed login attempts  
📅 **Time of Block**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

The user has been restricted from further access until reviewed by an administrator.

Please log in to the Admin Dashboard to review the activity and take necessary action.

---

Thank you,  
Smart Hospital Security System  
🔐 Keeping healthcare secure, one login at a time.
"""


    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.sendmail(sender_email, receiver_email, msg.as_string())
        print(f"📧 Email sent successfully for blocked user: {username}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management

# Generate decryption key and encryption cipher ONCE at server start
DECRYPTION_KEY = str(random.randint(100000, 999999))
FERNET_KEY = Fernet.generate_key()
init_encryption(DECRYPTION_KEY, FERNET_KEY)

print(f"\n🔑 Your decryption key (DO NOT SHARE): {DECRYPTION_KEY}\n")

# Load the trained ML model
with open('intrusion_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Sample user database (username, password, role)
users = {
    "admin": {"password": "admin123", "role": "admin", "status": "unblocked"},
    "admin2": {"password": "admin456", "role": "admin", "status": "unblocked"},
    "user1": {"password": "userpass1", "role": "user", "status": "unblocked"},
    "user2": {"password": "userpass2", "role": "user", "status": "unblocked"},
    "user3": {"password": "userpass3", "role": "user", "status": "unblocked"},
    "john_doe": {"password": "johndoe321", "role": "user", "status": "unblocked"},
    "alice_99": {"password": "alice1999", "role": "user", "status": "unblocked"},
    "mike_p": {"password": "mikepass", "role": "user", "status": "unblocked"},
    "sara_k": {"password": "sarak123", "role": "user", "status": "unblocked"},
    "kevin87": {"password": "kev!n87", "role": "user", "status": "unblocked"},
    "emma.green": {"password": "greenemma22", "role": "user", "status": "unblocked"},
    "rajiv": {"password": "rajiv2025", "role": "user", "status": "unblocked"},
}

# Track failed login attempts
failed_attempts = {}

# Store intrusion logs (only accessible by admin)
intrusion_logs = []

# 👇 ADDED FUNCTION
def save_intrusion_log(entry):
    os.makedirs("intrusion_logs", exist_ok=True)
    with open("intrusion_logs/suspicious_logs.txt", "a") as file:
        line = f"{entry['username']},{entry['time']},{entry['reason']}\n"
        file.write(line)

# Predict intrusion using the ML model
def predict_intrusion(username, password, attempts):
    input_features = np.array([[len(username), len(password), attempts]])
    prediction = model.predict(input_features)
    return prediction[0]  # 0 = Safe, 1 = Intrusion

@app.route('/')
def home():
    if request.args.get('logged_out'):
        flash("You have been logged out.", "info")
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.get(username)

        if user["status"] == "blocked":
            flash("🚫 Your account is blocked. Please contact the administrator.", "danger")
            return redirect('/')


        if not user:
            flash("⚠️ User does not exist!", "danger")
            return redirect('/')

        if username not in failed_attempts:
            failed_attempts[username] = 0

        if user['password'] == password:
            session['user'] = username
            session['role'] = user['role']
            failed_attempts[username] = 0

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'user':
                return redirect(url_for('user_dashboard'))
        else:
            failed_attempts[username] += 1
            prediction = predict_intrusion(username, password, failed_attempts[username])

            if prediction == 1 or failed_attempts[username] >= 3:
                entry = {
                    "username": username,
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "reason": "Multiple failed login attempts"
                }
                intrusion_logs.append(entry)
                save_intrusion_log(entry)
                users[username]["status"] = "blocked"  # 👈 block user
                send_block_alert_email(username)
                flash("🚨 Intrusion Detected! Your account is now blocked.", "danger")
                return redirect('/')
            else:
                flash(f"❌ Wrong Password! Attempts left: {3 - failed_attempts[username]}", "warning")
                return redirect('/')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user' in session and session['role'] == "admin":
        logs = []  # 👈 ADDED block below

        log_file_path = "intrusion_logs/suspicious_logs.txt"
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as file:
                for line in file:
                    parts = line.strip().split(',')
                    if len(parts) == 3:
                        logs.append({
                            "username": parts[0],
                            "time": parts[1],
                            "reason": parts[2]
                        })
        return render_template('admin_dashboard.html', logs=logs)
    else:
        flash("Unauthorized Access!", "danger")
        return redirect('/')

@app.route('/user_dashboard')
def user_dashboard():
    if 'user' in session and session['role'] == "user":
        return render_template('user_dashboard.html', username=session['user'])
    else:
        flash("Unauthorized Access!", "danger")
        return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('home', logged_out=True))

@app.route('/logout1')
def logout1():
    flash("You have been logged out.", "info")
    return redirect('/admin_dashboard')

@app.route('/blocked_users', methods=['GET'])
def blocked_users():
    if 'user' in session and session['role'] == "admin":
        blocked = [{"username": u} for u, data in users.items() if data["status"] == "blocked"]
        return {"users": blocked}
    return {"error": "Unauthorized"}, 403

@app.route('/unblock_user/<username>', methods=['POST'])
def unblock_user(username):
    if 'user' in session and session['role'] == "admin":
        if username in users:
            users[username]["status"] = "unblocked"
            return {"success": True}
    return {"error": "Unauthorized"}, 403



# ---------- Dataset Encryption & Viewing ----------

datasets = {}

def load_and_encrypt_dataset(file_path):
    df = pd.read_excel(file_path)
    headings = list(df.columns)
    encrypted_data = df.astype(str).map(encrypt_data).values.tolist()
    return headings, encrypted_data

datasets["vitals"] = {}
datasets["vitals"]["headings"], datasets["vitals"]["data"] = load_and_encrypt_dataset('dataset/vitals.xlsx')

datasets["careplan"] = {}
datasets["careplan"]["headings"], datasets["careplan"]["data"] = load_and_encrypt_dataset('dataset/careplan.xlsx')

datasets["medication"] = {}
datasets["medication"]["headings"], datasets["medication"]["data"] = load_and_encrypt_dataset('dataset/medication.xlsx')

datasets["devices"] = {}
datasets["devices"]["headings"], datasets["devices"]["data"] = load_and_encrypt_dataset('dataset/devices.xlsx')

@app.route('/dashboard')
def dashboard():
    if 'user' in session and session['role'] == "admin":
        return render_template('dashboard.html')
    else:
        return render_template('dashboard.html')

@app.route('/dataset/<category>', methods=['GET', 'POST'])
def view_dataset(category):
    if category not in datasets:
        return "Dataset not found", 404

    headings = datasets[category]["headings"]
    encrypted_data = datasets[category]["data"]
    decrypted = False

    if request.method == 'POST':
        key = request.form['decryption_key']
        decrypted_data = [[decrypt_data(cell, key) for cell in row] for row in encrypted_data]
        if "Invalid Key" not in decrypted_data[0]:
            encrypted_data = decrypted_data
            decrypted = True

    return render_template('index.html',
                           category=category.title(),
                           headings=headings,
                           encrypted_data=encrypted_data,
                           decrypted=decrypted)

@app.route('/view_medical_records')
def view_medical_records():
    return render_template('view_medical_records.html')

if __name__ == '__main__':
    app.run(debug=True)
