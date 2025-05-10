import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet

# ---------------------- Encryption Helpers ----------------------
def caesar_encrypt(text, shift=3):
    result = ''
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

fernet_key = base64.urlsafe_b64encode(hashlib.sha256(b"streamlit_secret").digest())
fernet = Fernet(fernet_key)

# ---------------------- Session Setup ----------------------
if 'users' not in st.session_state:
    st.session_state.users = {}
if 'data' not in st.session_state:
    st.session_state.data = {}
if 'user' not in st.session_state:
    st.session_state.user = None
if 'attempts' not in st.session_state:
    st.session_state.attempts = 0
if 'page' not in st.session_state:
    st.session_state.page = "Login"

# ---------------------- Login Page ----------------------
def login_register():
    st.title("🔐 Secure Storage | Login or Register")

    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        uname = st.text_input("Username", key="login_user")
        pwd = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            hashed = hashlib.sha256(pwd.encode()).hexdigest()
            if uname in st.session_state.users and st.session_state.users[uname] == hashed:
                st.session_state.user = uname
                st.session_state.page = "Home"
                st.session_state.attempts = 0
                st.success("✅ Login successful")
            else:
                st.error("❌ Invalid credentials")

    with tab2:
        new_uname = st.text_input("New Username")
        new_pwd = st.text_input("New Password", type="password")
        if st.button("Register"):
            if new_uname in st.session_state.users:
                st.warning("⚠️ Username already exists")
            else:
                st.session_state.users[new_uname] = hashlib.sha256(new_pwd.encode()).hexdigest()
                st.session_state.data[new_uname] = {}
                st.success("✅ Registered. Please log in.")

# ---------------------- Insert Data ----------------------
def insert_data():
    st.header("📝 Store Secure Data")
    key = st.text_input("Data Key")
    text = st.text_area("Enter Data")
    passkey = st.text_input("Secret Passkey", type="password")
    method = st.selectbox("Encryption Method", ["Fernet", "Caesar Cipher"])

    if st.button("Encrypt & Save"):
        if not key or not text or not passkey:
            st.warning("⚠️ Fill in all fields.")
            return
        if key in st.session_state.data[st.session_state.user]:
            st.error("❌ Key already used.")
            return

        hashed_pass = hashlib.sha256(passkey.encode()).hexdigest()
        encrypted = (
            fernet.encrypt(text.encode()).decode()
            if method == "Fernet"
            else caesar_encrypt(text)
        )

        st.session_state.data[st.session_state.user][key] = {
            "encrypted_text": encrypted,
            "passkey": hashed_pass,
            "method": method
        }
        st.success("✅ Data stored securely.")

# ---------------------- Retrieve Data ----------------------
def retrieve_data():
    st.header("🔍 Retrieve Secure Data")
    key = st.text_input("Data Key")
    passkey = st.text_input("Secret Passkey", type="password")

    if st.button("Decrypt"):
        user_data = st.session_state.data.get(st.session_state.user, {})
        if key not in user_data:
            st.error("❌ Key not found.")
            return

        entry = user_data[key]
        input_hash = hashlib.sha256(passkey.encode()).hexdigest()

        if input_hash == entry["passkey"]:
            decrypted = (
                fernet.decrypt(entry["encrypted_text"].encode()).decode()
                if entry["method"] == "Fernet"
                else caesar_decrypt(entry["encrypted_text"])
            )
            st.success("🔓 Decryption Successful")
            st.code(decrypted)
            st.session_state.attempts = 0
        else:
            st.session_state.attempts += 1
            tries_left = 3 - st.session_state.attempts
            st.error(f"❌ Wrong passkey. Attempts left: {tries_left}")
            if st.session_state.attempts >= 3:
                st.warning("🔒 Too many failed attempts. Redirecting to login...")
                st.session_state.user = None
                st.session_state.page = "Login"
                st.session_state.attempts = 0

# ---------------------- Home Page ----------------------
def home():
    st.title(f"🏠 Welcome, {st.session_state.user}")

    st.markdown("Use the sidebar to navigate.")

# ---------------------- Sidebar Navigation ----------------------
if st.session_state.user:
    st.sidebar.title("🔐 Navigation")
    option = st.sidebar.radio("Go to", ["Home", "Insert Data", "Retrieve Data", "Logout"])

    if option == "Home":
        home()
    elif option == "Insert Data":
        insert_data()
    elif option == "Retrieve Data":
        retrieve_data()
    elif option == "Logout":
        st.session_state.user = None
        st.session_state.page = "Login"
        st.success("✅ Logged out.")
else:
    login_register()
