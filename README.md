# 🔐 Secure Data Storage App

A simple, secure data encryption and retrieval system built with **Streamlit**, designed for safe in-memory storage using custom **passkeys**, **Fernet/Caesar encryption**, and **user-based authentication**.

---

## ✅ Features

- 🔑 User registration and login system (no hardcoded users)
- 🔐 Secure encryption using **Fernet** or **Caesar Cipher**
- 🗃️ Store multiple entries per user, each with a unique key
- 🔓 Decrypt entries using the correct passkey
- 🚫 Lockout and forced reauthentication after 3 failed attempts
- 🧠 In-memory storage (no external databases)
- 🎛️ Sidebar for intuitive page navigation

---

## 🧰 Technologies Used

- [Streamlit](https://streamlit.io/)
- [cryptography](https://pypi.org/project/cryptography/) (`Fernet` encryption)
- Python standard libraries (`hashlib`, `base64`, `collections`)

---

## 🚀 How to Run

1. **Clone or download the repository**
   ```bash
   git clone https://github.com/your-username/secure-data-app.git
   cd secure-data-app
🧪 How It Works
1. User Authentication
Register with a custom username and password.

Login is required to access the app.

After 3 incorrect retrieval attempts, you're logged out for reauthentication.

2. Insert Data
Choose your encryption method (Fernet or Caesar).

Input your data, assign a unique key, and a secret passkey.

Data is encrypted, hashed, and stored in-memory under your user profile.

3. Retrieve Data
Provide the correct key and passkey.

Decryption only succeeds if the hash of your input matches the original.


