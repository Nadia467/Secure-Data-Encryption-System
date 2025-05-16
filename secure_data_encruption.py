import streamlit as st
import hashlib
from cryptography.fernet import Fernet  # type: ignore

# 🔐 Generate a key (store this securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# 🗂️ In-memory data storage
stored_data = {}  # Format: {"encrypted_text": {"encrypted_text": ..., "passkey": ...}}
failed_attempts = 0

# 🔑 Hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# 🔒 Encrypt plain text
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# 🔓 Decrypt only if passkey matches
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for value in stored_data.values():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    failed_attempts += 1
    return None

# 🚀 Streamlit UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Securely **store** and **retrieve** data using encryption.")

elif choice == "Store Data":
    st.subheader("📥 Store Data")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data, passkey)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and saved.")
        else:
            st.warning("⚠️ Both fields are required.")

elif choice == "Retrieve Data":
    st.subheader("📤 Retrieve Data")
    encrypted_input = st.text_area("Enter encrypted text:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success(f"✅ Decrypted: {result}")
            else:
                st.error(f"❌ Incorrect passkey. Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Returning to Login...")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Both fields are required.")

elif choice == "Login":
    st.subheader("🔑 Login")
    master_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Reauthorized. Going back to Retrieve tab...")
            st.experimental_rerun()
        else:
            st.error("❌ Wrong password.")
